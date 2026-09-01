#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include <stdint.h>
#include <sys/ioctl.h>

#include "files.h"
#include "pidfd.pb-c.h"
#include "pidfs.pb-c.h"

/*
 * PIDFD_GET_INFO (pidfs ioctl, Linux 6.13) lets us read the exit status of
 * the process a pidfd refers to. The struct layout is versioned by size and
 * baked into the ioctl number, and the kernel serves any request at least as
 * large as the first published version. So we deliberately pin our own copy
 * to that version (PIDFD_INFO_SIZE_VER0 == 64 bytes) rather than track the
 * ones added since: @exit_code, all we need, is its last field. This needs no
 * <linux/pidfd.h> and works unchanged on every kernel that has the ioctl.
 */
struct criu_pidfd_info {
	uint64_t mask;
	uint64_t cgroupid;
	uint32_t pid;
	uint32_t tgid;
	uint32_t ppid;
	uint32_t ruid;
	uint32_t rgid;
	uint32_t euid;
	uint32_t egid;
	uint32_t suid;
	uint32_t sgid;
	uint32_t fsuid;
	uint32_t fsgid;
	int32_t exit_code;
};

/* Only returned by PIDFD_GET_INFO if requested and the task has exited. */
#define CRIU_PIDFD_INFO_EXIT (1UL << 3)
#define CRIU_PIDFD_GET_INFO  _IOWR(0xFF, 11, struct criu_pidfd_info)

/*
 * A process that has been reaped stays observable through its struct pid: a
 * pidfd of it can still be held, the kernel can still hand one out for an skb
 * it sent, and pidfs keeps its exit status readable via PIDFD_GET_INFO.
 *
 * To reproduce that, restore forks a stand-in process for each such dead pid,
 * lets everything that needs to reference it do so -- open a pidfd of it, pass
 * its pid to sendmsg() as spoofed SCM_CREDENTIALS -- and only then makes the
 * stand-in die exactly the way the original did. The references then go stale
 * with the right exit status, just as they were before the dump.
 *
 * Stand-ins are keyed on the pidfs ino of the struct pid they stand in for,
 * in one hashtable shared by everything that restores a reference to a dead
 * pid -- pidfd files and the queued packets of dead senders alike. That is
 * what makes the identities come out right: two references to one dead
 * process get one stand-in, and two dead processes get two, however alike
 * they happen to look. Nothing else about a reaped process is distinctive
 * enough to key on; two of them can share an exit code, a name, everything.
 *
 * An entry with no ino recorded (see pidfs_attr_entry) gets a stand-in of its
 * own, shared with nothing, since there is no way to tell what it is.
 *
 * The table is global to one restoring task, not to the restore, because a
 * stand-in is a child of the task that forked it. For pidfd files that is
 * enough: collect_one_pidfd() elects a single creator per dead struct pid and
 * open_one_pidfd() sends the fds it opens to the other tasks, so they all
 * come from one place. Queued packets have no such mechanism, so two tasks
 * restoring sockets that hold packets from one dead sender -- or one holding
 * the packets and another holding a pidfd of the same sender -- still end up
 * with a stand-in each, and a receiver sees two inos where there was one.
 * Fixing that means routing dead senders through a creator task the way
 * pidfds already are.
 *
 * dead_pid_put_all() makes every stand-in die and reaps it. It has to run
 * once all the references are taken, so it is called from open_fdinfos() once
 * the task has restored all of its files, not by the individual open methods.
 */
extern pid_t dead_pid_get(uint64_t ino, bool has_ino, PidfsAttrEntry *attr);
extern int dead_pid_put_all(void);

extern const struct fdtype_ops pidfd_dump_ops;
extern struct collect_image_info pidfd_cinfo;
extern int is_pidfd_link(char *link);
extern void init_dead_pidfd_hash(void);
extern int pidfd_query_exit(int pidfd, int *exit_code);
extern int pidfd_query_ino(int pidfd, uint64_t *ino);
struct pidfd_dump_info {
	PidfdEntry pidfe;
	pid_t pid;
};

#endif /* __CR_PIDFD_H__ */
