#ifndef __CR_PIDFD_H__
#define __CR_PIDFD_H__

#include "files.h"
#include "pidfd.pb-c.h"

extern const struct fdtype_ops pidfd_dump_ops;
extern struct collect_image_info pidfd_cinfo;
extern int is_pidfd_link(char *link);
extern void init_dead_pidfd_hash(void);
extern pid_t create_tmp_process(void);
extern int kill_helper(pid_t pid);
extern pid_t parse_pidfd_pid(int pidfd);
struct pidfd_dump_info {
	PidfdEntry pidfe;
	pid_t pid;
};

#endif /* __CR_PIDFD_H__ */
