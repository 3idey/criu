#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that SCM_CREDENTIALS are preserved in the socket queue";
const char *test_author	= "Ahmed Elaidy";

static int send_creds(int sk)
{
	char cbuf[CMSG_SPACE(sizeof(struct ucred))];
	struct cmsghdr *cmsg;
	struct msghdr mh = {};
	struct ucred *uc;
	struct iovec iov;
	char c = 'x';
	int one = 1;

	if (setsockopt(sk, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one))) {
		pr_perror("setsockopt SO_PASSCRED");
		return -1;
	}

	memset(cbuf, 0, sizeof(cbuf));
	mh.msg_control = cbuf;
	mh.msg_controllen = sizeof(cbuf);
	cmsg = CMSG_FIRSTHDR(&mh);
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

static int recv_creds(int sk, uid_t expect_uid, gid_t expect_gid)
{
	char cbuf[CMSG_SPACE(sizeof(struct ucred))];
	struct msghdr mh = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct ucred *uc;
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

	cmsg = CMSG_FIRSTHDR(&mh);
	if (!cmsg || cmsg->cmsg_type != SCM_CREDENTIALS) {
		fail("No SCM_CREDENTIALS in received message");
		return -1;
	}

	uc = (struct ucred *)CMSG_DATA(cmsg);

	if (uc->uid != expect_uid) {
		fail("uid mismatch: got %u, expected %u", uc->uid, expect_uid);
		return -1;
	}

	if (uc->gid != expect_gid) {
		fail("gid mismatch: got %u, expected %u", uc->gid, expect_gid);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	uid_t my_uid;
	gid_t my_gid;
	int sk[2];

	test_init(argc, argv);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sk)) {
		pr_perror("socketpair");
		return 1;
	}

	my_uid = getuid();
	my_gid = getgid();

	/* Send SCM_CREDENTIALS into sk[1]'s receive queue via sk[0] */
	if (send_creds(sk[0])) {
		fail("send_creds");
		return 1;
	}

	test_daemon();
	test_waitsig();

	/*
	 * After restore, verify that the SCM_CREDENTIALS message
	 * survived C/R and contains the correct uid/gid. The pid
	 * field is allowed to differ (it will be remapped to the
	 * restored process's PID).
	 */
	if (recv_creds(sk[1], my_uid, my_gid)) {
		/* fail() already called inside recv_creds */
		return 1;
	}

	pass();
	return 0;
}
