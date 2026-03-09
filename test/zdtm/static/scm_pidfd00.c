#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "zdtmtst.h"

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif

#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

const char *test_doc	= "Check that a live SCM_PIDFD is preserved across C/R";
const char *test_author	= "Ahmed Elaidy";

static int pidfd_send_signal(int pidfd, int sig, siginfo_t *info,
			     unsigned int flags)
{
	return syscall(__NR_pidfd_send_signal, pidfd, sig, info, flags);
}

/*
 * Send a single byte over the socket. The receiver has SO_PASSPIDFD
 * enabled, so the kernel will attach an SCM_PIDFD for the sender.
 */
static int send_msg(int sk)
{
	struct iovec iov;
	struct msghdr mh = {};
	char c = 'p';

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

/*
 * Receive the message and verify that SCM_PIDFD is attached.
 * The pidfd should reference a live process, so pidfd_send_signal
 * with signal 0 must succeed.
 */
static int recv_pidfd(int sk)
{
	char cbuf[CMSG_SPACE(sizeof(int))];
	struct msghdr mh = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	int pidfd;
	char c;

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

	cmsg = CMSG_FIRSTHDR(&mh);
	if (!cmsg || cmsg->cmsg_type != SCM_PIDFD) {
		fail("No SCM_PIDFD in received message (type=%d)",
		     cmsg ? cmsg->cmsg_type : -1);
		return -1;
	}

	pidfd = *(int *)CMSG_DATA(cmsg);

	/* Verify the pidfd references a live process */
	if (pidfd_send_signal(pidfd, 0, NULL, 0)) {
		fail("pidfd_send_signal(0) failed: %s", strerror(errno));
		close(pidfd);
		return -1;
	}

	close(pidfd);
	return 0;
}

int main(int argc, char *argv[])
{
	int sk[2];
	int one = 1;
	pid_t child;
	int status;

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

	/*
	 * Fork a child so the pidfd references a different process.
	 * The child sends a message, then waits for the test to finish.
	 */
	child = fork();
	if (child < 0) {
		pr_perror("fork");
		return 1;
	}

	if (child == 0) {
		close(sk[1]);
		if (send_msg(sk[0]))
			_exit(1);
		/* Wait until parent is done */
		test_waitsig();
		_exit(0);
	}

	close(sk[0]);

	test_daemon();
	test_waitsig();

	/* After restore, receive and verify the SCM_PIDFD */
	if (recv_pidfd(sk[1])) {
		kill(child, SIGTERM);
		waitpid(child, &status, 0);
		return 1;
	}

	kill(child, SIGTERM);
	waitpid(child, &status, 0);

	pass();
	return 0;
}
