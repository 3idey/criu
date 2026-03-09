#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "zdtmtst.h"

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

const char *test_doc	= "Check all three SCM types (RIGHTS + CREDENTIALS + PIDFD) in one message";
const char *test_author	= "Ahmed Elaidy";

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			     unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

/*
 * Send a message with SCM_RIGHTS + SCM_CREDENTIALS.
 * The receiver has both SO_PASSCRED and SO_PASSPIDFD enabled,
 * so the kernel attaches SCM_PIDFD as well on receive.
 */
static int send_all(int sk, int fd_to_send)
{
	char cbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
	struct cmsghdr *cmsg;
	struct msghdr mh = {};
	struct iovec iov;
	struct ucred *uc;
	char c = 'a';
	int one = 1;

	if (setsockopt(sk, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) {
		pr_perror("setsockopt SO_PASSCRED");
		return -1;
	}

	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);

	/* SCM_RIGHTS */
	cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = fd_to_send;

	/* SCM_CREDENTIALS */
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

static int recv_all(int sk, uid_t expect_uid, gid_t expect_gid)
{
	char cbuf[CMSG_SPACE(sizeof(int)) * 3 + CMSG_SPACE(sizeof(struct ucred))];
	struct msghdr mh = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	int got_rights = 0, got_creds = 0, got_pidfd = 0;
	int recv_fd = -1, pidfd = -1;
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
		} else if (cmsg->cmsg_type == SCM_PIDFD) {
			pidfd = *(int *)CMSG_DATA(cmsg);
			got_pidfd = 1;
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
	if (!got_pidfd) {
		fail("No SCM_PIDFD in received message");
		return -1;
	}

	/* Verify the pidfd references a live process */
	if (pidfd_send_signal(pidfd, 0, NULL, 0)) {
		fail("pidfd_send_signal(0) failed: %s", strerror(errno));
		close(pidfd);
		if (recv_fd >= 0)
			close(recv_fd);
		return -1;
	}

	/* Verify the received fd is functional */
	if (fcntl(recv_fd, F_GETFD) < 0) {
		fail("Received fd %d is not valid: %s", recv_fd,
		     strerror(errno));
		close(pidfd);
		close(recv_fd);
		return -1;
	}

	close(pidfd);
	close(recv_fd);
	return 0;
}

int main(int argc, char *argv[])
{
	uid_t my_uid;
	gid_t my_gid;
	int sk[2];
	int one = 1;
	pid_t child;
	int status;
	int fd;

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk)) {
		pr_perror("socketpair");
		return 1;
	}

	/* Enable SO_PASSPIDFD on the receiving end */
	if (setsockopt(sk[1], SOL_SOCKET, SO_PASSPIDFD, &one, sizeof(one))) {
		if (errno == ENOPROTOOPT) {
			skip("Kernel does not support SO_PASSPIDFD");
			return 1;
		}
		pr_perror("setsockopt SO_PASSPIDFD");
		return 1;
	}

	fd = open("/dev/null", O_RDONLY);
	if (fd < 0) {
		pr_perror("open /dev/null");
		return 1;
	}

	my_uid = getuid();
	my_gid = getgid();

	/*
	 * Fork a child to send the message so the pidfd references
	 * a different (live) process.
	 */
	child = fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}

	if (child == 0) {
		close(sk[1]);
		if (send_all(sk[0], fd))
			_exit(1);
		close(fd);
		test_waitsig();
		_exit(0);
	}

	close(sk[0]);
	close(fd);

	test_daemon();
	test_waitsig();

	/* After restore, verify all three SCM types survive */
	if (recv_all(sk[1], my_uid, my_gid)) {
		kill(child, SIGTERM);
		waitpid(child, &status, 0);
		return 1;
	}

	kill(child, SIGTERM);
	waitpid(child, &status, 0);

	pass();
	return 0;
}
