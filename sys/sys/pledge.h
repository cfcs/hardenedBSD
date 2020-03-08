#ifndef _SYS_PLEDGE_H
#define _SYS_PLEDGE_H

#include <sys/stdint.h>
#include <sys/types.h>
#include <sys/tree.h>

/*
 * Structure used to return recorded learning data via the sysctl
 *   security.pledge.learning_data
 * when the learning mode is in effect, ie when sysctl
 *   security.pledge.learning = 1
 * Exposed to both kernel and userland.
 */
typedef struct pledge_learning_entry_t {
	/* Tracks whether or not this entry is populated: */
	u_int is_populated;
	/* pledge flags both possessed and actively utilized: */
	uint64_t used_flags;
	/* pledge flags not possessed, but required for successful operation: */
	uint64_t violated_flags;
	/* pledge flags possessed */
	uint64_t possessed;
	ino_t inode; /* inode of executable that triggered this */
	dev_t fsid;  /* fsid of executable that triggered this */
} pledge_learning_entry_t;

/*
 * RB tree definitions used internally in the kernel and in /usr/sbin/pledgectl.
 * The kernel walks such a tree structure and returns an
 * array in response to the security.pledge.learning_data sysctl to avoid having
 * to fix up kernelspace pointers, but this structure can also be used in user
 * programs that need to do frequent access by inode, which is why it is
 * exposed here.
 * See: man 3 tree
 */

/*
 * Tree element definition
 */
typedef struct pledge_splay_t {
	RB_ENTRY(pledge_splay_t) tree_link;
	/* key: */
	ino_t inode;
	dev_t fs_id;
	/* values: */
	uint64_t used;
	uint64_t violated;
	uint64_t possessed;
} pledge_splay_t;

/*
 * TODO provide this + implementation as macro?
 */
/* TODO
static int learning_splay_compare(
	const pledge_splay_t *_a,
	const pledge_splay_t *_b);
*/
/* kernel functions: */
#ifdef _KERNEL

#include "opt_pledge.h"
#include <sys/sysproto.h>
#include <sys/vnode.h>

/* TODO document that most of these may crash the thread if
 * PLEDGE_SOFTFAIL is not set */

/* check if a thread has a given set of flags TODO document properly */
int pledge_check_bitmap(struct thread *thread, const uint64_t flags);

/* kernel-land function to restrict pledge permission mask for thread: */
int kern_pledge(struct thread *thread, const uint64_t mask);

/* syscall to restrict pledge permission mask for thread: */
/*int sys_pledge(struct thread *thread, struct pledge_args *args); TODO */

/* hook for the syscall handler to determine if syscall_no may be called: */
int pledge_syscall(struct thread *thread, const int syscall_no);

/* hook for open() access. */
int pledge_openat(struct thread *thread, const int fd, const char *path,
    const int flags, const int mode);

int pledge_apply_extattr(struct thread *td, struct vnode *ni_vp);

#endif /* _KERNEL */


/* pledge(2) flags */
/* TODO would have been awful nice if C permitted uint64_t-backed enums so
 * we could avoid this mess... */

#define PLEDGE_NONE			0ULL	/* empty mask */
#define PLEDGE_AND		(1ULL <<  0)	/* match ALL flags */
#define PLEDGE_SOFTFAIL	(1ULL <<  1)	/* return EPERM instead of crashing */

/* These names (not the constants) are copied from OpenBSD,
 * maybe we can have some interopability to easy porting: */

#define PLEDGE_RPATH		(1ULL <<  2)	/* allow open for read */
#define PLEDGE_WPATH		(1ULL <<  3)	/* allow open for write */
#define PLEDGE_CPATH		(1ULL <<  4)	/* allow creat, mkdir, unlink etc */
#define PLEDGE_STDIO		(1ULL <<  5)	/* operate on own pid */
#define PLEDGE_TMPPATH		(1ULL <<  6)	/* for mk*temp() */
#define PLEDGE_DNS		(1ULL <<  7)	/* DNS services */
#define PLEDGE_INET		(1ULL <<  8)	/* AF_INET/AF_INET6 sockets */
#define PLEDGE_FLOCK		(1ULL <<  9)	/* file locking */
#define PLEDGE_UNIX		(1ULL << 10)	/* AF_UNIX sockets */
#define PLEDGE_ID		(1ULL << 11)	/* allow setuid, setgid, etc */
#define PLEDGE_TAPE		(1ULL << 12)	/* Tape ioctl */
#define PLEDGE_GETPW		(1ULL << 13)	/* YP enables if ypbind.lock */
#define PLEDGE_PROC		(1ULL << 14)	/* fork, waitpid, etc */
#define PLEDGE_SETTIME		(1ULL << 15)	/* able to set/adj time/freq */
#define PLEDGE_FATTR		(1ULL << 16)	/* allow explicit file st_* mods */
#define PLEDGE_PROTEXEC	(1ULL << 17)	/* allow use of PROT_EXEC */
#define PLEDGE_TTY		(1ULL << 18)	/* tty setting */
#define PLEDGE_SENDFD		(1ULL << 19)	/* AF_UNIX CMSG fd sending */
#define PLEDGE_RECVFD		(1ULL << 20)	/* AF_UNIX CMSG fd receiving */
#define PLEDGE_EXEC		(1ULL << 21)	/* execve, child is free of pledge */
#define PLEDGE_ROUTE		(1ULL << 22)	/* routing lookups */
#define PLEDGE_MCAST		(1ULL << 23)	/* multicast joins */
#define PLEDGE_VMINFO		(1ULL << 24)	/* vminfo listings */
#define PLEDGE_PS		(1ULL << 25)	/* ps listings */
#define PLEDGE_DISKLABEL	(1ULL << 26)	/* disklabels */
#define PLEDGE_PF		(1ULL << 27)	/* pf ioctls */
#define PLEDGE_AUDIO		(1ULL << 28)	/* audio ioctls */
#define PLEDGE_DPATH		(1ULL << 29)	/* mknod & mkfifo */
#define PLEDGE_DRM		(1ULL << 30)	/* drm ioctls */
#define PLEDGE_VMM		(1ULL << 31)	/* vmm ioctls */
#define PLEDGE_CHOWN		(1ULL << 32)	/* chown(2) family */
#define PLEDGE_CHOWNUID	(1ULL << 33)	/* allow owner/group changes */
#define PLEDGE_BPF		(1ULL << 34)	/* bpf ioctl */

/* HardenedBSD-specific constants:*/

/* CPATH,FATTR,CHOWN under /dev
 * mount, unmount, mknod
 * RPATH,WPATH under /dev when doing so requires non-world permissions
 */
#define PLEDGE_DEVICE	(1ULL << 45)	/* modify devices, mount, unmount */
#define PLEDGE_KLD	(1ULL << 46)	/* things to do with loadable modules */

#define PLEDGE_WILDCARD	((~0ULL) ^ \
	    (PLEDGE_AND | PLEDGE_SOFTFAIL))	/* match any flag */

static const
struct {
	const uint64_t constant;
	const char *name;
} pledge_string_map[] = {
	{ PLEDGE_AND,		"&"},
	{ PLEDGE_WILDCARD,	"wildcard" },
	{ PLEDGE_RPATH,	"rpath" },
	{ PLEDGE_WPATH,	"wpath" },
	{ PLEDGE_CPATH,	"cpath" },
	{ PLEDGE_STDIO,	"stdio" },
	{ PLEDGE_TMPPATH,	"tmppath" },
	{ PLEDGE_DNS,		"dns" },
	{ PLEDGE_INET,		"inet" },
	{ PLEDGE_FLOCK,	"dns" },
	{ PLEDGE_UNIX,		"unix" },
	{ PLEDGE_ID,		"id" },
	{ PLEDGE_TAPE,		"tape" },
	{ PLEDGE_GETPW,	"getpw" },
	{ PLEDGE_PROC,		"proc" },
	{ PLEDGE_SETTIME,	"settime" },
	{ PLEDGE_FATTR,	"fattr" },
	{ PLEDGE_PROTEXEC,	"protexec" },
	{ PLEDGE_TTY,		"tty" },
	{ PLEDGE_SENDFD,	"sendfd" },
	{ PLEDGE_RECVFD,	"recvfd" },
	{ PLEDGE_EXEC,		"exec" },
	{ PLEDGE_ROUTE,	"route" },
	{ PLEDGE_MCAST,	"mcast" },
	{ PLEDGE_VMINFO,	"vminfo" },
	{ PLEDGE_PS,		"ps" },
	{ PLEDGE_DISKLABEL,	"disklabel" },
	{ PLEDGE_PF,		"pf" },
	{ PLEDGE_AUDIO,	"audio" },
	{ PLEDGE_DPATH,	"dpath" },
	{ PLEDGE_DRM,		"drm" },
	{ PLEDGE_VMM,		"vmm" },
	{ PLEDGE_CHOWN,	"chown" },
	{ PLEDGE_CHOWNUID,	"chownuid" },
	{ PLEDGE_BPF,		"bpf" },
	{ PLEDGE_DEVICE,	"device" },
	{ PLEDGE_KLD,		"kld" },
	{ PLEDGE_SOFTFAIL,	"softfail" },
	{ PLEDGE_NONE,		"none"}
};


#endif /* _SYS_PLEDGE_H */
