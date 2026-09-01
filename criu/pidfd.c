#include "common/lock.h"
#include "imgset.h"
#include "kerndat.h"
#include "pidfd.h"
#include "fdinfo.h"
#include "pidfd.pb-c.h"
#include "protobuf.h"
#include "pstree.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include "common/bug.h"
#include "common/compiler.h"
#include "rst-malloc.h"
#include "util.h"

#include "compel/plugins/std/syscall-codes.h"

#undef LOG_PREFIX
#define LOG_PREFIX "pidfd: "

#ifndef PIDFD_THREAD
#define PIDFD_THREAD O_EXCL
#endif

struct pidfd_info {
	PidfdEntry *pidfe;
	struct file_desc d;

	struct dead_pidfd *dead;
	struct pidfd_info *next;
};

struct dead_pidfd {
	uint64_t ino;
	int creator_id;

	struct hlist_node hash;
	struct pidfd_info *list;
};

#define DEAD_PIDFD_HASH_SIZE 32
static struct hlist_head dead_pidfd_hash[DEAD_PIDFD_HASH_SIZE];

void init_dead_pidfd_hash(void)
{
	for (int i = 0; i < DEAD_PIDFD_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&dead_pidfd_hash[i]);
}

static struct dead_pidfd *lookup_dead_pidfd(uint64_t ino)
{
	struct dead_pidfd *dead;
	struct hlist_head *chain;

	chain = &dead_pidfd_hash[ino % DEAD_PIDFD_HASH_SIZE];
	hlist_for_each_entry(dead, chain, hash) {
		if (dead->ino == ino) {
			return dead;
		}
	}

	return NULL;
}

/*
 * Query the exit status of the process a pidfd refers to via PIDFD_GET_INFO.
 * Returns 1 and fills *exit_code (a wait(2)-style status word) if the task has
 * exited, 0 if it is still alive, and -1 if the ioctl is unavailable or failed
 * (the caller should fall back to a coarser method).
 */
int pidfd_query_exit(int pidfd, int *exit_code)
{
	struct criu_pidfd_info info = { .mask = CRIU_PIDFD_INFO_EXIT };

	BUILD_BUG_ON(sizeof(struct criu_pidfd_info) != 64);

	if (ioctl(pidfd, CRIU_PIDFD_GET_INFO, &info) < 0) {
		pr_debug("PIDFD_GET_INFO failed: %s\n", strerror(errno));
		return -1;
	}

	if (!(info.mask & CRIU_PIDFD_INFO_EXIT))
		return 0;

	*exit_code = info.exit_code;
	return 1;
}

/*
 * Read the pidfs inode number of the struct pid @pidfd refers to. This is the
 * identity of the process: pidfs hands every struct pid a unique inode (Linux
 * 6.9), and comparing inode numbers is how the kernel itself tells two pidfds
 * apart.
 *
 * Returns 0 and fills *ino on success, -1 on failure. Note that this is not
 * the convention pidfd_query_exit() above uses -- that one has a third answer
 * to give ("the task is still alive"), this one does not.
 */
int pidfd_query_ino(int pidfd, uint64_t *ino)
{
	struct stat st;

	if (fstat(pidfd, &st) < 0) {
		pr_debug("fstat on pidfd %d failed: %s\n", pidfd, strerror(errno));
		return -1;
	}

	*ino = st.st_ino;
	return 0;
}

int is_pidfd_link(char *link)
{
	/*
	* pidfs was introduced in Linux 6.9
	* before which anonymous-inodes were used
	*/
	return is_anon_link_type(link, "[pidfd]");
}

static void pr_info_pidfd(char *action, PidfdEntry *pidfe)
{
	pr_info("%s: id %#08x flags %u NSpid %d ino %" PRIu64 "\n",
		action, pidfe->id, pidfe->flags, pidfe->nspid, pidfe->ino
	);
}

static int dump_one_pidfd(int pidfd, u32 id, const struct fd_parms *p)
{
	struct pidfd_dump_info pidfd_info = {.pidfe = PIDFD_ENTRY__INIT};
	PidfsAttrEntry attr = PIDFS_ATTR_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	int exit_code;

	if (parse_fdinfo(pidfd, FD_TYPES__PIDFD, &pidfd_info))
		return -1;

	if (p->flags & PIDFD_THREAD) {
		pr_err("PIDFD_THREAD flag is currently not supported\n");
		return -1;
	}

	/*
	* Check if the pid pidfd refers to is part of process tree
	* This ensures the process will exist on restore.
	*/
	if (pidfd_info.pid != -1 && !pstree_item_by_real(pidfd_info.pid)) {
		pr_err("pidfd pid %d is not a part of process tree..\n",
			pidfd_info.pid);
		return -1;
	}

	/*
	 * The task has been reaped, so all that is left of it is what pidfs
	 * stashed on its struct pid. Save the exit status, so that the
	 * stand-in process restore forks for this dead pid can die the same
	 * way and PIDFD_GET_INFO keeps reporting it.
	 */
	if (pidfd_info.pid == -1 && kdat.has_pidfd_get_info &&
	    pidfd_query_exit(pidfd, &exit_code) > 0) {
		attr.has_exit_code = true;
		attr.exit_code = exit_code;
		pidfd_info.pidfe.attr = &attr;
	}

	pidfd_info.pidfe.id = id;
	pidfd_info.pidfe.flags = (p->flags & ~O_RDWR);
	pidfd_info.pidfe.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__PIDFD;
	fe.id = pidfd_info.pidfe.id;
	fe.pidfd = &pidfd_info.pidfe;

	pr_info_pidfd("Dumping", &pidfd_info.pidfe);
	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops pidfd_dump_ops = {
	.type = FD_TYPES__PIDFD,
	.dump = dump_one_pidfd,
};

static int pidfd_open(pid_t pid, int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int create_tmp_process(void)
{
	int tmp_process;
	tmp_process = fork();
	if (tmp_process < 0) {
		pr_perror("Could not fork");
		return -1;
	} else if (tmp_process == 0) {
		/* Nothing would reap us if criu died before kill_helper(). */
		prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		/* We need none of the task's files, see create_status_helper(). */
		close_fds(3);
		while(1)
			sleep(1);
	}
	return tmp_process;
}

/*
 * A restore-time stand-in for a process that was already dead at dump time.
 * Without @has_status the original exit status is unknown and a plain SIGKILL
 * is the best we can reproduce.
 */
struct dead_pid {
	struct dead_pid *next;
	struct hlist_node hash;
	uint64_t ino;
	bool has_ino;
	pid_t pid;
	bool has_status;
	int status;
};

/*
 * Stand-ins live only for as long as one task is restoring its files, and are
 * forked by that task, so this table needs no initializer: a static hlist head
 * is a NULL pointer, which is an empty chain.
 */
#define DEAD_PID_HASH_SIZE 32
static struct hlist_head dead_pid_hash[DEAD_PID_HASH_SIZE];
static struct dead_pid *dead_pid_list;

static struct dead_pid *lookup_dead_pid(uint64_t ino)
{
	struct dead_pid *dp;

	hlist_for_each_entry(dp, &dead_pid_hash[ino % DEAD_PID_HASH_SIZE], hash) {
		if (dp->ino == ino)
			return dp;
	}

	return NULL;
}

/*
 * The signal a status helper waits for. Any signal would do: it is blocked
 * from the moment the helper is forked (criu restore runs with signals
 * blocked), so it can never be lost or act early, and the helper consumes it
 * with sigwait() rather than letting it have any effect of its own. That also
 * leaves it free to die *by* this signal, if that is how the process it
 * stands in for died.
 */
#define DEAD_PID_GO SIGUSR1

/*
 * Fork a helper that waits until we tell it to die, then reproduces an
 * arbitrary wait(2) status: it exits with a given code or raises a given
 * signal. This is how a stand-in for a dead pid gets the exit status the
 * process it stands in for had. Tell it to die with kill_status_helper().
 *
 * @status is passed by nothing more than the fork: the child gets its own
 * copy along with the rest of our memory. Deliberately so -- a helper must
 * hold no file descriptor of ours, since it outlives the open method that
 * forked it and any fd it kept would sit in the way of a file this task has
 * still to restore.
 */
static int create_status_helper(int status)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Could not fork status helper");
		return -1;
	}

	if (pid == 0) {
		sigset_t set;
		int sig;

		/*
		 * Nothing would reap us if criu died before it got around to
		 * kill_status_helper().
		 */
		prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
		/*
		 * fork() handed us a copy of every file the task has restored
		 * so far, and we outlive the open method that forked us. Drop
		 * them, or we would pin the other end of a pipe or a socket
		 * well past the point the task meant to close it.
		 */
		close_fds(3);

		sigemptyset(&set);
		sigaddset(&set, DEAD_PID_GO);
		sigprocmask(SIG_BLOCK, &set, NULL);
		if (sigwait(&set, &sig) != 0)
			_exit(1);

		if (WIFEXITED(status)) {
			_exit(WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			sigset_t unblock;

			sig = WTERMSIG(status);

			/*
			 * We are forked from a criu process that runs with
			 * signals blocked, so unblock the one we are about to
			 * raise -- otherwise it would only become pending and
			 * we would fall through to _exit() below.
			 */
			sigemptyset(&unblock);
			sigaddset(&unblock, sig);
			sigprocmask(SIG_UNBLOCK, &unblock, NULL);

			/*
			 * Don't dump core for a fatal-signal death. A side
			 * effect is that the restored exit status never carries
			 * the WCOREDUMP() bit, even if the process we stand in
			 * for did dump core; reproducing that bit (and the
			 * pidfs coredump attributes along with it) is
			 * deliberately skipped, and kill_status_helper() only
			 * checks the terminating signal.
			 */
			prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
			signal(sig, SIG_DFL);
			raise(sig);
		}
		_exit(1);
	}

	return pid;
}

/*
 * Block SIGCHLD to prevent interfering from sigchld_handler() and to properly
 * handle the tmp process termination without a race condition. A similar
 * approach is used in cr_system().
 */
static int helper_block_sigchld(sigset_t *oldmask)
{
	sigset_t blockmask;

	sigemptyset(oldmask);
	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blockmask, oldmask) == -1) {
		pr_perror("Cannot set mask of blocked signals");
		return -1;
	}
	return 0;
}

static int kill_helper(pid_t pid)
{
	int status;
	sigset_t oldmask;

	if (helper_block_sigchld(&oldmask))
		goto err;

	if (kill(pid, SIGKILL) < 0) {
		pr_perror("Could not kill temporary process with pid: %d", pid);
		goto err;
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Could not wait on temporary process with pid: %d", pid);
		goto err;
	}

	/* Restore the original signal mask after tmp process has terminated */
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Cannot clear blocked signals");
		goto err;
	}

	if (!WIFSIGNALED(status)) {
		pr_err("Expected temporary process to be terminated by a signal\n");
		goto err;
	}

	if (WTERMSIG(status) != SIGKILL) {
		pr_err("Expected temporary process to be terminated by SIGKILL\n");
		goto err;
	}

	return 0;
err:
	return -1;
}

/*
 * Make a create_status_helper() child die with @status (a wait(2)-style
 * status word) and reap it, verifying it died exactly as asked.
 */
static int kill_status_helper(pid_t pid, int status)
{
	sigset_t oldmask;
	int wstatus;
	int ret = -1;
	bool blocked = false, reaped = false;

	if (helper_block_sigchld(&oldmask))
		goto out;
	blocked = true;

	if (kill(pid, DEAD_PID_GO) < 0) {
		pr_perror("Could not signal status helper %d to exit", pid);
		goto out;
	}

	if (waitpid(pid, &wstatus, 0) != pid) {
		pr_perror("Could not wait on status helper with pid: %d", pid);
		goto out;
	}
	reaped = true;

	if (WIFEXITED(status)) {
		if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != WEXITSTATUS(status)) {
			pr_err("Status helper %d did not exit with code %d\n", pid, WEXITSTATUS(status));
			goto out;
		}
	} else if (WIFSIGNALED(status)) {
		if (!WIFSIGNALED(wstatus) || WTERMSIG(wstatus) != WTERMSIG(status)) {
			pr_err("Status helper %d was not killed by signal %d\n", pid, WTERMSIG(status));
			goto out;
		}
	}

	ret = 0;
out:
	/*
	 * On the error paths the child may still be running -- never signalled
	 * at all, or signalled but not reaped. Kill and reap it so we neither
	 * leak a zombie nor leave SIGCHLD blocked in the caller.
	 */
	if (!reaped && pid > 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
	}
	if (blocked && sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Cannot clear blocked signals");
		ret = -1;
	}
	return ret;
}

/*
 * Return the pid of a stand-in process for the dead struct pid with pidfs
 * inode @ino, forking one if this is the first reference to it. @has_ino is
 * false when the dump could not record an identity, in which case the caller
 * gets a stand-in all of its own rather than one shared by guesswork. @attr
 * may be NULL, or carry no exit code, when the way the process died is not
 * known.
 */
pid_t dead_pid_get(uint64_t ino, bool has_ino, PidfsAttrEntry *attr)
{
	bool has_status = attr && attr->has_exit_code;
	int status = has_status ? attr->exit_code : 0;
	struct dead_pid *dp;
	pid_t pid;

	if (has_ino) {
		dp = lookup_dead_pid(ino);
		if (dp) {
			pr_debug("Reusing stand-in %d for dead pid ino %" PRIu64 "\n",
				 dp->pid, ino);
			return dp->pid;
		}
	}

	if (has_status)
		pid = create_status_helper(status);
	else
		pid = create_tmp_process();
	if (pid < 0)
		return -1;

	dp = xmalloc(sizeof(*dp));
	if (!dp) {
		kill_helper(pid);
		return -1;
	}

	dp->pid = pid;
	dp->has_status = has_status;
	dp->status = status;
	dp->ino = ino;
	dp->has_ino = has_ino;
	dp->next = dead_pid_list;
	dead_pid_list = dp;

	INIT_HLIST_NODE(&dp->hash);
	if (has_ino) {
		hlist_add_head(&dp->hash, &dead_pid_hash[ino % DEAD_PID_HASH_SIZE]);
		pr_debug("Forked stand-in %d for dead pid ino %" PRIu64 "\n", pid, ino);
	} else {
		pr_debug("Forked stand-in %d for a dead pid of unknown identity\n", pid);
	}

	return pid;
}

/*
 * Make every stand-in die the way the process it stands in for did, and reap
 * it. Call this only once everything that needs to reference these dead pids
 * has done so: each reference -- an open pidfd, an skb holding the struct pid
 * -- keeps the pid around, so it goes stale exactly as it was before the dump.
 */
int dead_pid_put_all(void)
{
	struct dead_pid *dp, *next;
	int ret = 0;

	for (dp = dead_pid_list; dp; dp = next) {
		next = dp->next;
		if (dp->has_status) {
			if (kill_status_helper(dp->pid, dp->status))
				ret = -1;
		} else if (kill_helper(dp->pid)) {
			ret = -1;
		}
		if (dp->has_ino)
			hlist_del(&dp->hash);
		xfree(dp);
	}
	dead_pid_list = NULL;

	return ret;
}

static int open_one_pidfd(struct file_desc *d, int *new_fd)
{
	struct pidfd_info *info, *child;
	struct dead_pidfd *dead = NULL;
	pid_t pid;
	int pidfd = -1;

	info = container_of(d, struct pidfd_info, d);
	if (info->pidfe->nspid != -1) {
		pidfd = pidfd_open(info->pidfe->nspid, info->pidfe->flags);
		if (pidfd < 0) {
			pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
			goto err_close;
		}
		goto out;
	}

	dead = lookup_dead_pidfd(info->pidfe->ino);
	BUG_ON(!dead);

	if (info->dead && info->dead->creator_id != info->pidfe->id) {
		int ret = recv_desc_from_peer(&info->d, &pidfd);
		if (ret != 0) {
			if (ret != 1)
				pr_err("Can't get fd\n");
			return ret;
		}
		goto out;
	}

	/*
	 * Nothing of the original process is left but its struct pid, so stand
	 * in for it with a process that dies the way the original did.
	 *
	 * The stand-in is keyed on the pidfs ino, so anything else in this task
	 * that refers to the same dead process -- another pidfd, a queued
	 * packet it sent -- lands on this very same one. It is killed in
	 * open_fdinfos(), once all of them have taken their reference.
	 *
	 * A zero ino is not an identity: the ino: line of /proc/pid/fdinfo/N is
	 * not required to be there, and taking its absence for a shared
	 * identity would collapse every dead pidfd onto one stand-in. Ask for a
	 * private one instead.
	 */
	pid = dead_pid_get(info->pidfe->ino, info->pidfe->ino != 0, info->pidfe->attr);
	if (pid < 0)
		goto err_close;

	for (child = dead->list; child; child = child->next) {
		int cfd;

		if (child == info)
			continue;
		cfd = pidfd_open(pid, child->pidfe->flags);
		if (cfd < 0) {
			pr_perror("Could not open pidfd for %d", child->pidfe->nspid);
			goto err_close;
		}

		if (send_desc_to_peer(cfd, &child->d)) {
			pr_perror("Can't send file descriptor");
			close(cfd);
			goto err_close;
		}
		close(cfd);
	}

	pidfd = pidfd_open(pid, info->pidfe->flags);
	if (pidfd < 0) {
		pr_perror("Could not open pidfd for %d", info->pidfe->nspid);
		goto err_close;
	}
out:
	if (rst_file_params(pidfd, info->pidfe->fown, info->pidfe->flags)) {
		goto err_close;
	}

	*new_fd = pidfd;
	return 0;
err_close:
	if (pidfd >= 0)
		close(pidfd);
	pr_err("Can't create pidfd %#08x NSpid: %d flags: %u\n",
	   info->pidfe->id, info->pidfe->nspid, info->pidfe->flags);
	return -1;
}

static struct file_desc_ops pidfd_desc_ops = {
	.type = FD_TYPES__PIDFD,
	.open = open_one_pidfd
};

static int collect_one_pidfd(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct dead_pidfd *dead;
	struct pidfd_info *info = obj;

	info->pidfe = pb_msg(msg, PidfdEntry);
	pr_info_pidfd("Collected ", info->pidfe);

	info->dead = NULL;
	if (info->pidfe->nspid != -1)
		goto out;

	dead = lookup_dead_pidfd(info->pidfe->ino);
	if (!dead) {
		dead = xmalloc(sizeof(*dead));
		if (!dead) {
			pr_err("Could not allocate memory..\n");
			return -1;
		}

		INIT_HLIST_NODE(&dead->hash);
		dead->list = NULL;
		dead->ino = info->pidfe->ino;
		dead->creator_id = info->pidfe->id;
		hlist_add_head(&dead->hash, &dead_pidfd_hash[dead->ino % DEAD_PIDFD_HASH_SIZE]);
	}

	info->dead = dead;
	info->next = dead->list;
	dead->list = info;
	if (dead->creator_id > info->pidfe->id)
		dead->creator_id = info->pidfe->id;

out:
	return file_desc_add(&info->d, info->pidfe->id, &pidfd_desc_ops);
}

struct collect_image_info pidfd_cinfo = {
	.fd_type = CR_FD_PIDFD,
	.pb_type = PB_PIDFD,
	.priv_size = sizeof(struct pidfd_info),
	.collect = collect_one_pidfd,
};
