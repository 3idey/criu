#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "common/list.h"
#include "imgset.h"
#include "image.h"
#include "servicefd.h"
#include "cr_options.h"
#include "util.h"
#include "util-pie.h"
#include "sockets.h"
#include "xmalloc.h"
#include "sk-queue.h"
#include "files.h"
#include "protobuf.h"
#include "images/sk-packet.pb-c.h"
#include "pstree.h"
#include "pidfd.h"
#include "kerndat.h"

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#undef LOG_PREFIX
#define LOG_PREFIX "skqueue: "

struct sk_packet {
	struct list_head list;
	SkPacketEntry *entry;
	char *data;
	unsigned scm_len;
	int *scm;
	pid_t scm_helper; /* tmp process for SCM_PIDFD injection */
};

static LIST_HEAD(packets_list);

static int collect_one_packet(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	struct sk_packet *pkt = obj;

	pkt->entry = pb_msg(msg, SkPacketEntry);
	pkt->scm = NULL;
	pkt->scm_helper = 0;
	pkt->data = xmalloc(pkt->entry->length);
	if (pkt->data == NULL)
		return -1;

	/*
	 * See dump_packet_cmsg() -- at most 1 SCM_RIGHTS, 1
	 * SCM_CREDENTIALS, and 1 SCM_PIDFD per packet.
	 */
	if (pkt->entry->n_scm > 3) {
		pr_err("More than 3 SCMs per packet is not supported\n");
		xfree(pkt->data);
		return -1;
	}

	if (read_img_buf(img, pkt->data, pkt->entry->length) != 1) {
		xfree(pkt->data);
		pr_perror("Unable to read packet data");
		return -1;
	}

	/*
	 * NOTE: packet must be added to the tail. Otherwise sequence
	 * will be broken.
	 */
	list_add_tail(&pkt->list, &packets_list);

	return 0;
}

struct collect_image_info sk_queues_cinfo = {
	.fd_type = CR_FD_SK_QUEUES,
	.pb_type = PB_SK_QUEUES,
	.priv_size = sizeof(struct sk_packet),
	.collect = collect_one_packet,
};

static int dump_scm_rights(struct cmsghdr *ch, SkPacketEntry *pe)
{
	int nr_fds, *fds, i;
	void *buf;
	ScmEntry *scme;

	nr_fds = (ch->cmsg_len - sizeof(*ch)) / sizeof(int);
	fds = (int *)CMSG_DATA(ch);

	buf = xmalloc(sizeof(ScmEntry) + nr_fds * sizeof(uint32_t));
	if (!buf)
		return -1;

	scme = xptr_pull(&buf, ScmEntry);
	scm_entry__init(scme);
	scme->type = SCM_RIGHTS;
	scme->n_rights = nr_fds;
	scme->rights = xptr_pull_s(&buf, nr_fds * sizeof(uint32_t));

	for (i = 0; i < nr_fds; i++) {
		int ftyp;

		if (dump_my_file(fds[i], &scme->rights[i], &ftyp)) {
			xfree(scme);
			return -1;
		}
	}

	i = pe->n_scm++;
	if (xrealloc_safe(&pe->scm, pe->n_scm * sizeof(ScmEntry *))) {
		pe->n_scm--;
		xfree(scme);
		return -1;
	}

	pe->scm[i] = scme;
	return 0;
}

static int dump_scm_credentials(struct cmsghdr *ch, SkPacketEntry *pe)
{
	struct ucred *ucred = (struct ucred *)CMSG_DATA(ch);
	SkUcredEntry *uce;
	ScmEntry *scme;
	void *buf;
	int i;

	buf = xmalloc(sizeof(ScmEntry) + sizeof(SkUcredEntry));
	if (!buf)
		return -1;

	scme = xptr_pull(&buf, ScmEntry);
	scm_entry__init(scme);
	scme->type = SCM_CREDENTIALS;
	uce = xptr_pull(&buf, SkUcredEntry);
	sk_ucred_entry__init(uce);
	uce->pid = ucred->pid;
	uce->uid = ucred->uid;
	uce->gid = ucred->gid;
	scme->cred = uce;

	i = pe->n_scm++;
	if (xrealloc_safe(&pe->scm, pe->n_scm * sizeof(ScmEntry *))) {
		pe->n_scm--;
		xfree(scme);
		return -1;
	}

	pe->scm[i] = scme;
	return 0;
}

static int dump_scm_pidfd(struct cmsghdr *ch, SkPacketEntry *pe)
{
	int pidfd = *(int *)CMSG_DATA(ch);
	SkPidfdScmEntry *pse;
	ScmEntry *scme;
	struct stat st;
	void *buf;
	pid_t pid;
	int i;

	pid = parse_pidfd_pid(pidfd);

	buf = xmalloc(sizeof(ScmEntry) + sizeof(SkPidfdScmEntry));
	if (!buf) {
		close(pidfd);
		return -1;
	}

	scme = xptr_pull(&buf, ScmEntry);
	scm_entry__init(scme);
	scme->type = SCM_PIDFD;
	pse = xptr_pull(&buf, SkPidfdScmEntry);
	sk_pidfd_scm_entry__init(pse);

	if (pid < 0) {
		/*
		 * parse_pidfd_pid returns -1 when the referenced
		 * process has already exited (fdinfo shows Pid: -1).
		 * Mark it stale; we don't need the original pid for
		 * restore -- a temporary helper process will be used.
		 */
		pse->pid = 0;
		pse->has_ino = true;
		pse->ino = 0;
		pse->has_stale = true;
		pse->stale = true;
	} else {
		if (fstat(pidfd, &st) < 0) {
			pr_perror("Failed to fstat pidfd %d", pidfd);
			close(pidfd);
			xfree(scme);
			return -1;
		}
		pse->pid = pid;
		pse->has_ino = true;
		pse->ino = st.st_ino;
		pse->has_stale = true;
		pse->stale = (kill(pid, 0) == -1 && errno == ESRCH);
	}

	close(pidfd);
	scme->pidfd = pse;

	i = pe->n_scm++;
	if (xrealloc_safe(&pe->scm, pe->n_scm * sizeof(ScmEntry *))) {
		pe->n_scm--;
		xfree(scme);
		return -1;
	}

	pe->scm[i] = scme;
	return 0;
}

/*
 * Maximum size of the control messages. XXX -- is there any
 * way to get this value out of the kernel?
 * */
#define CMSG_MAX_SIZE 1024

static int dump_packet_cmsg(struct msghdr *mh, SkPacketEntry *pe)
{
	struct cmsghdr *ch;
	int n_rights = 0;
	int n_creds = 0;

	for (ch = CMSG_FIRSTHDR(mh); ch; ch = CMSG_NXTHDR(mh, ch)) {
		if (ch->cmsg_type == SCM_RIGHTS) {
			if (n_rights) {
				/*
				 * Even if user is sending more than one cmsg with
				 * rights, kernel merges them altogether on recv.
				 */
				pr_err("Unexpected 2nd SCM_RIGHTS from the kernel\n");
				return -1;
			}

			if (dump_scm_rights(ch, pe))
				return -1;

			n_rights++;
			continue;
		}

		if (ch->cmsg_type == SCM_CREDENTIALS) {
			if (n_creds) {
				pr_err("Unexpected 2nd SCM_CREDENTIALS from the kernel\n");
				return -1;
			}

			if (dump_scm_credentials(ch, pe))
				return -1;

			n_creds++;
			continue;
		}

		if (ch->cmsg_type == SCM_PIDFD) {
			if (dump_scm_pidfd(ch, pe))
				return -1;
			continue;
		}

		pr_err("Control messages in queue, not supported\n");
		return -1;
	}

	return 0;
}

static void release_cmsg(SkPacketEntry *pe)
{
	int i;

	for (i = 0; i < pe->n_scm; i++)
		xfree(pe->scm[i]);
	xfree(pe->scm);

	pe->n_scm = 0;
	pe->scm = NULL;
}

int dump_sk_queue(int sock_fd, int sock_id)
{
	SkPacketEntry pe = SK_PACKET_ENTRY__INIT;
	int ret, size, orig_peek_off;
	int orig_passcred = 0;
	int orig_passpidfd = 0;
	void *data;
	socklen_t tmp;

	/*
	 * Save original peek offset.
	 */
	tmp = sizeof(orig_peek_off);
	orig_peek_off = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}
	/*
	 * Discover max DGRAM size
	 */
	tmp = sizeof(size);
	size = 0;
	ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &size, &tmp);
	if (ret < 0) {
		pr_perror("getsockopt failed");
		return ret;
	}

	/* Note: 32 bytes will be used by kernel for protocol header. */
	size -= 32;

	/*
	 * Allocate data for a stream.
	 */
	data = xmalloc(size);
	if (!data)
		return -1;

	/*
	 * Enable peek offset incrementation.
	 */
	ret = setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (ret < 0) {
		pr_perror("setsockopt fail");
		goto err_brk;
	}

	pe.id_for = sock_id;

	/*
	 * Temporarily enable SO_PASSCRED so that the peek loop
	 * below can see any SCM_CREDENTIALS control messages that
	 * reside in the queue.  The kernel only delivers these
	 * cmsgs when the receiving socket has the flag set.
	 */
	tmp = sizeof(orig_passcred);
	if (getsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED,
		       &orig_passcred, &tmp) == 0 && !orig_passcred) {
		int one = 1;

		if (setsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED,
			       &one, sizeof(one))) {
			pr_perror("Unable to set SO_PASSCRED for peek");
			goto err_brk;
		}
	}

	/*
	 * Similarly, temporarily enable SO_PASSPIDFD so that the
	 * peek loop can see SCM_PIDFD control messages.  The kernel
	 * generates SCM_PIDFD on recvmsg only when SO_PASSPIDFD is
	 * set on the receiving socket.
	 */
	if (kdat.has_so_passpidfd) {
		tmp = sizeof(orig_passpidfd);
		if (getsockopt(sock_fd, SOL_SOCKET, SO_PASSPIDFD,
			       &orig_passpidfd, &tmp) == 0 &&
		    !orig_passpidfd) {
			int one = 1;

			if (setsockopt(sock_fd, SOL_SOCKET, SO_PASSPIDFD,
				       &one, sizeof(one))) {
				pr_perror("Unable to set SO_PASSPIDFD for peek");
				goto err_set_sock;
			}
		}
	}

	while (1) {
		char cmsg[CMSG_MAX_SIZE];
		struct iovec iov = {
			.iov_base = data,
			.iov_len = size,
		};
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = &cmsg,
			.msg_controllen = sizeof(cmsg),
		};

		ret = pe.length = recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (!ret)
			/*
			 * It means, that peer has performed an
			 * orderly shutdown, so we're done.
			 */
			break;
		else if (ret < 0) {
			if (errno == EAGAIN)
				break; /* we're done */
			pr_perror("recvmsg fail: error");
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM truncated. This should not happen. But we have
			 * to check...
			 */
			pr_err("sys_recvmsg failed: truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_CTRUNC) {
			/*
			 * Control data truncated. This means the cmsg
			 * buffer was too small and SCM data (such as
			 * passed file descriptors) has been silently
			 * discarded by the kernel.
			 */
			pr_err("sys_recvmsg failed: control data truncated\n");
			ret = -E2BIG;
			goto err_set_sock;
		}

		if (dump_packet_cmsg(&msg, &pe))
			goto err_set_sock;

		ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SK_QUEUES), &pe, PB_SK_QUEUES);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		ret = write_img_buf(img_from_set(glob_imgset, CR_FD_SK_QUEUES), data, pe.length);
		if (ret < 0) {
			ret = -EIO;
			goto err_set_sock;
		}

		if (pe.scm)
			release_cmsg(&pe);
	}
	ret = 0;

err_set_sock:
	/*
	 * Restore original SO_PASSPIDFD value.
	 */
	if (kdat.has_so_passpidfd && !orig_passpidfd) {
		int zero = 0;

		setsockopt(sock_fd, SOL_SOCKET, SO_PASSPIDFD,
			   &zero, sizeof(zero));
	}

	/*
	 * Restore original SO_PASSCRED value.
	 */
	if (!orig_passcred) {
		int zero = 0;

		setsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED,
			   &zero, sizeof(zero));
	}

	/*
	 * Restore original peek offset.
	 */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int))) {
		pr_perror("setsockopt failed on restore");
		ret = -1;
	}
	if (pe.scm)
		release_cmsg(&pe);
err_brk:
	xfree(data);
	return ret;
}

/*
 * Resolve virtual pids in SCM control messages to real pids.
 * Called at sendmsg time when all processes have been forked.
 */
static int resolve_scm_pids(struct sk_packet *pkt)
{
	SkPacketEntry *pe = pkt->entry;
	char *buf = (char *)pkt->scm;
	bool has_creds = false;
	int i;

	for (i = 0; i < pe->n_scm; i++) {
		if (pe->scm[i]->type == SCM_CREDENTIALS) {
			has_creds = true;
			break;
		}
	}

	for (i = 0; i < pe->n_scm; i++) {
		ScmEntry *se = pe->scm[i];

		if (se->type == SCM_RIGHTS) {
			buf += CMSG_SPACE(se->n_rights * sizeof(int));
			continue;
		}

		if (se->type == SCM_CREDENTIALS) {
			struct cmsghdr *ch = (struct cmsghdr *)buf;
			struct ucred *uc = (struct ucred *)CMSG_DATA(ch);
			struct pstree_item *item;

			item = pstree_item_by_virt(se->cred->pid);
			if (!item) {
				pr_warn("SCM_CREDENTIALS: pid %d not in pstree, using CRIU's pid\n",
					se->cred->pid);
				uc->pid = getpid();
			} else {
				uc->pid = item->pid->real;
			}

			buf += CMSG_SPACE(sizeof(struct ucred));
			continue;
		}

		if (se->type == SCM_PIDFD) {
			struct cmsghdr *ch;
			struct ucred *uc;

			/*
			 * Skipped by prepare_scms() when the packet
			 * has explicit SCM_CREDENTIALS.
			 */
			if (has_creds)
				continue;

			ch = (struct cmsghdr *)buf;
			uc = (struct ucred *)CMSG_DATA(ch);

			/*
			 * Stale pidfds use a helper process whose pid
			 * was already placed by prepare_scms().
			 */
			if (!se->pidfd->stale) {
				struct pstree_item *item;

				item = pstree_item_by_virt(se->pidfd->pid);
				if (!item) {
					pr_warn("SCM_PIDFD: pid %d not in pstree, using CRIU's pid\n",
						se->pidfd->pid);
					uc->pid = getpid();
				} else {
					uc->pid = item->pid->real;
				}
			}

			buf += CMSG_SPACE(sizeof(struct ucred));
			continue;
		}
	}

	return 0;
}

static int send_one_pkt(int fd, struct sk_packet *pkt)
{
	int ret;
	SkPacketEntry *entry = pkt->entry;
	struct msghdr mh = {};
	struct iovec iov;

	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	iov.iov_base = pkt->data;
	iov.iov_len = entry->length;

	if (pkt->scm != NULL) {
		resolve_scm_pids(pkt);
		mh.msg_controllen = pkt->scm_len;
		mh.msg_control = pkt->scm;
	}

	/*
	 * Don't try to use sendfile here, because it use sendpage() and
	 * all data are split on pages and a new skb is allocated for
	 * each page. It creates a big overhead on SNDBUF.
	 * sendfile() isn't suitable for DGRAM sockets, because message
	 * boundaries messages should be saved.
	 */

	ret = sendmsg(fd, &mh, 0);
	xfree(pkt->data);
	xfree(pkt->scm);
	if (pkt->scm_helper) {
		if (kill_helper(pkt->scm_helper))
			pr_warn("Failed to kill SCM_PIDFD helper %d\n",
				pkt->scm_helper);
		pkt->scm_helper = 0;
	}
	if (ret < 0) {
		pr_perror("Failed to send packet");
		return -1;
	}
	if (ret != entry->length) {
		pr_err("Restored skb trimmed to %d/%d\n", ret, (unsigned int)entry->length);
		return -1;
	}

	return 0;
}

int restore_sk_queue(int fd, unsigned int peer_id)
{
	struct sk_packet *pkt, *tmp;
	int ret = -1;

	pr_info("Trying to restore recv queue for %u\n", peer_id);

	if (restore_prepare_socket(fd))
		goto out;

	list_for_each_entry_safe(pkt, tmp, &packets_list, list) {
		SkPacketEntry *entry = pkt->entry;

		if (entry->id_for != peer_id)
			continue;

		pr_info("\tRestoring %d-bytes skb for %u\n", (unsigned int)entry->length, peer_id);

		ret = send_one_pkt(fd, pkt);
		if (ret)
			goto out;

		list_del(&pkt->list);
		sk_packet_entry__free_unpacked(entry, NULL);
		xfree(pkt);
	}

	ret = 0;
out:
	return ret;
}

int prepare_scms(void)
{
	struct sk_packet *pkt;

	pr_info("Preparing SCMs\n");
	list_for_each_entry(pkt, &packets_list, list) {
		SkPacketEntry *pe = pkt->entry;
		char *buf;
		size_t total = 0;
		int i;
		bool has_creds = false;

		if (!pe->n_scm)
			continue;

		/*
		 * Check if this packet has explicit SCM_CREDENTIALS.
		 * If so, SCM_PIDFD entries are redundant: the kernel
		 * stores only one UNIXCB(skb).pid per skb, and the
		 * receiver's SO_PASSPIDFD will derive SCM_PIDFD from
		 * it.  Sending both would cause the SCM_PIDFD entry
		 * (with uid=0) to overwrite the real credentials.
		 */
		for (i = 0; i < pe->n_scm; i++) {
			if (pe->scm[i]->type == SCM_CREDENTIALS) {
				has_creds = true;
				break;
			}
		}

		/* First pass: calculate total control message buffer size */
		for (i = 0; i < pe->n_scm; i++) {
			ScmEntry *se = pe->scm[i];

			if (se->type == SCM_RIGHTS)
				total += CMSG_SPACE(se->n_rights * sizeof(int));
			else if (se->type == SCM_CREDENTIALS)
				total += CMSG_SPACE(sizeof(struct ucred));
			else if (se->type == SCM_PIDFD) {
				if (has_creds)
					continue;
				/*
				 * Injected as SCM_CREDENTIALS: the receiving
				 * socket's SO_PASSPIDFD converts it to SCM_PIDFD.
				 */
				total += CMSG_SPACE(sizeof(struct ucred));
			} else {
				pr_err("Unsupported scm %d in image\n", se->type);
				return -1;
			}
		}

		pkt->scm_len = total;
		pkt->scm = xmalloc(total);
		if (!pkt->scm)
			return -1;
		memset(pkt->scm, 0, total);

		/* Second pass: fill control message buffer */
		buf = (char *)pkt->scm;
		for (i = 0; i < pe->n_scm; i++) {
			ScmEntry *se = pe->scm[i];
			struct cmsghdr *ch = (struct cmsghdr *)buf;

			if (se->type == SCM_RIGHTS) {
				ch->cmsg_level = SOL_SOCKET;
				ch->cmsg_type = SCM_RIGHTS;
				ch->cmsg_len = CMSG_LEN(se->n_rights * sizeof(int));

				if (unix_note_scm_rights(pe->id_for, se->rights,
						(int *)CMSG_DATA(ch), se->n_rights))
					return -1;

				buf += CMSG_SPACE(se->n_rights * sizeof(int));
				continue;
			}

			if (se->type == SCM_CREDENTIALS) {
				struct ucred *uc;

				ch->cmsg_level = SOL_SOCKET;
				ch->cmsg_type = SCM_CREDENTIALS;
				ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));

				uc = (struct ucred *)CMSG_DATA(ch);
				uc->uid = se->cred->uid;
				uc->gid = se->cred->gid;
				uc->pid = 0; /* resolved later by resolve_scm_pids */

				buf += CMSG_SPACE(sizeof(struct ucred));
				continue;
			}

			if (se->type == SCM_PIDFD) {
				struct ucred *uc;

				/*
				 * If the packet already has SCM_CREDENTIALS,
				 * skip: the kernel stores one UNIXCB per skb
				 * and the last SCM_CREDENTIALS wins, so a
				 * duplicate would overwrite the real uid/gid.
				 */
				if (has_creds)
					continue;

				/*
				 * SCM_PIDFD cannot be injected directly
				 * (__scm_send rejects it). Instead, inject
				 * SCM_CREDENTIALS with the right PID; the
				 * receiving socket's SO_PASSPIDFD will derive
				 * SCM_PIDFD from UNIXCB(skb).pid on recv.
				 */
				ch->cmsg_level = SOL_SOCKET;
				ch->cmsg_type = SCM_CREDENTIALS;
				ch->cmsg_len = CMSG_LEN(sizeof(struct ucred));

				uc = (struct ucred *)CMSG_DATA(ch);
				uc->uid = 0;
				uc->gid = 0;

				if (se->pidfd->stale) {
					/*
					 * Stale pidfd: fork a helper process
					 * whose pid is embedded in the skb;
					 * kill it after sendmsg completes.
					 */
					pid_t pid = create_tmp_process();
					if (pid < 0)
						return -1;
					uc->pid = pid;
					pkt->scm_helper = pid;
				} else {
					uc->pid = 0; /* resolved later */
				}

				buf += CMSG_SPACE(sizeof(struct ucred));
				continue;
			}
		}
	}

	return 0;
}
