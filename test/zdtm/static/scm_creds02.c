#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check mixed SCM_RIGHTS + SCM_CREDENTIALS in one message";
const char *test_author	= "Ahmed Elaidy";

static int send_mixed(int sk, int fd_to_send)
{
	char cbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
	struct cmsghdr *cmsg;
	struct msghdr mh = {};
	struct iovec iov;
	struct ucred *uc;
	char c = 'm';
	int one = 1;

	if (setsockopt(sk, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) {
		pr_perror("setsockopt SO_PASSCRED");
		return -1;
	}

	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	/* First cmsg: SCM_RIGHTS */
	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = fd_to_send;

	/* Second cmsg: SCM_CREDENTIALS */
	cmsg = CMSG_NXTHDR(&mh, cmsg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_CREDENTIALS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
	uc = (struct ucred *)CMSG_DATA(cmsg);
	uc->pid = getpid();
	uc->uid = getuid();
	uc->gid = getgid();

	iov.iov_base = &c;
	iov.iov_len = sizeof(c);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	if (sendmsg(sk, &mh, 0) != sizeof(c)) {
		pr_perror("sendmsg");
		return -1;
	}

	return 0;
}

static int recv_mixed(int sk, uid_t expect_uid, gid_t expect_gid)
{
	char cbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
	struct msghdr mh = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	int got_rights = 0, got_creds = 0;
	int recv_fd = -1;
	char c;
	int one = 1;

	if (setsockopt(sk, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) {
		pr_perror("setsockopt SO_PASSCRED (recv)");
		return -1;
	}

	iov.iov_base = &c;
	iov.iov_len = sizeof(c);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	if (recvmsg(sk, &mh, 0) != sizeof(c)) {
		pr_perror("recvmsg");
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_type == SCM_RIGHTS) {
			recv_fd = *(int *)CMSG_DATA(cmsg);
			got_rights = 1;
		} else if (cmsg->cmsg_type == SCM_CREDENTIALS) {
			struct ucred *uc = (struct ucred *)CMSG_DATA(cmsg);

			if (uc->uid != expect_uid) {
				fail("uid mismatch: got %u, expected %u",
				     uc->uid, expect_uid);
				return -1;
			}
			if (uc->gid != expect_gid) {
				fail("gid mismatch: got %u, expected %u",
				     uc->gid, expect_gid);
				return -1;
			}
			got_creds = 1;
		}
	}

	if (!got_rights) {
		fail("No SCM_RIGHTS in received message");
		return -1;
	}

	if (!got_creds) {
		fail("No SCM_CREDENTIALS in received message");
		return -1;
	}

	/* Verify the received fd is functional */
	if (fcntl(recv_fd, F_GETFD) < 0) {
		fail("Received fd %d is not valid: %s", recv_fd,
		     strerror(errno));
		return -1;
	}

	close(recv_fd);
	return 0;
}

int main(int argc, char *argv[])
{
	uid_t my_uid;
	gid_t my_gid;
	int sk[2];
	int fd;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk)) {
		pr_perror("socketpair");
		return 1;
	}

	/* Open a file to send as SCM_RIGHTS */
	fd = open("/dev/null", O_RDONLY);
	if (fd < 0) {
		pr_perror("open /dev/null");
		return 1;
	}

	my_uid = getuid();
	my_gid = getgid();

	if (send_mixed(sk[0], fd)) {
		fail("send_mixed");
		return 1;
	}

	close(fd);

	test_daemon();
	test_waitsig();

	if (recv_mixed(sk[1], my_uid, my_gid))
		return 1;

	pass();
	return 0;
}
