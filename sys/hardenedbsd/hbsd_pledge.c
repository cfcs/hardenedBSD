#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_pledge.h"

#ifdef HBSD_PLEDGE

/* TOOD determine overlap with man 9 priv,
   which defaults to checking euid/jail status when determining
  allowed privileges
  a good place to patch in overlapping things would
  probably be priv_check()/priv_check_cred()
*/

#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/extattr.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/param.h>
#include <sys/pledge.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/pledge.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/tree.h>
#include <sys/counter.h>
#include <sys/lock.h>
#include <sys/rmlock.h>
#include <machine/atomic.h>

FEATURE(hbsd_hardening, "Pledge sandbox mechanism");

SDT_PROVIDER_DECLARE(pledge);
SDT_PROVIDER_DEFINE(pledge);


/* DTrace probe for recording privilege transitions (drops).
   pid, 0, 0, td->td_pledge, requested_mask.
   The zeroes are placeholders for fsid/inode, which unfortunately are expensive to obtain.
   TODO consider thread generation or similar identifying information,
   alternatively we could trace the vnode pointer to the executable, which
   could then be paired with a DTrace probe on process creation to obtain
   the path of the executable.
*/
SDT_PROBE_DEFINE5(pledge, kern, kern_pledge, masks,
    "pid_t", "uint64_t", "uint64_t", "uint64_t", "uint64_t");

/*
 * TODO dwatch tooling
 * DTrace SDT probe for recording violations of the pledge mask.
 * This provides a live view of the data available through the
 * security.pledge.learning_data sysctl.
 * reference: man 9 SDT
 * The arguments are (in this order):
 * - pid
 * - fsid
 * - inode
 * - syscall number
 * - the current pledge mask possessed by thread
 * - the violated mask.
 * - the used mask
 * - TODO we should add additional fields like zfs txgid
 */
SDT_PROBE_DEFINE7(pledge, learning, insert, masks,
    "pid_t", "uint64_t", "ino_t", "int", "uint64_t", "uint64_t", "uint64_t");

/*
 * Global exported symbols
 */

bool pledge_learning = 0;
bool pledge_enforcing = 0; /* TODO: = HBSD_PLEDGE; */


/*
 * Forward declarations for static functions and variables in this file:
 */

static int sysctl_pledge_flags(SYSCTL_HANDLER_ARGS);
static int sysctl_pledge_learning_data(SYSCTL_HANDLER_ARGS);

static void pledge_learning_init(const void *_unused);
static void pledge_learning_record(const struct thread *,
    const uint64_t, const uint64_t);

/* see pledge.h for:
 * - splay element type learning_splay_t
 */

/* second: comparison function */
static int learning_tree_compare(
	const pledge_splay_t *_a,
	const pledge_splay_t *_b);
static int
learning_tree_compare(
	const struct pledge_splay_t *a,
	const struct pledge_splay_t *b)
{
	const ino_t i_diff = a->inode - b->inode;
	return (i_diff || (a->fs_id - b->fs_id));
}

/*
 * DPCPU(9)-sized array of tree root structs
 * TODO should we have __aligned(CACHE_LINE_SIZE) on RB_HEAD here and in the splay_entries array?
 */
typedef RB_HEAD(learning_tree, pledge_splay_t) learning_tree_t;
DPCPU_DEFINE_STATIC(learning_tree_t, learning_tree);

/*
 * Lock controlling insertion (write) and foreach/find (read) access to
 * the learning_tree array:
 */
DPCPU_DEFINE_STATIC(struct rmlock, learning_rm_lock);

RB_PROTOTYPE_STATIC(learning_tree,
    pledge_splay_t, tree_link, learning_tree_compare);

RB_GENERATE_STATIC(learning_tree,
    pledge_splay_t, tree_link, learning_tree_compare);


/* Initialize the learning mode structure before SI_SUB_CREATE_INIT
 * so we are ready for the first /sbin/init process:
 */

SYSINIT(pledge_sysinit_learning, SI_SUB_AUDIT, SI_ORDER_ANY,
    pledge_learning_init, NULL);


/*
 * sysctl declarations for security.pledge.*:
 * security.pledge.learning - toggle learning mode
 * security.pledge.learning_data - retrieve learning data
 * security.pledge.violations - violation counter
 * security.pledge.kills - counter of killed processes
 * security.pledge.softfails - counter of softfailed syscalls
 * security.pledge.enforcing - toggle enforcing mode
 * security.pledge.flags - get/set thread pledge bitmap
 */

SYSCTL_NODE(_security, OID_AUTO, pledge, 0, 0,
    "pledge policy controls");

SYSCTL_BOOL(_security_pledge, OID_AUTO, learning,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY | /* HardenedBSD-specific */
#endif
    CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_RWTUN,
    &pledge_learning, 0,
    "record pledge violations (0: off, 1: learning)");

SYSCTL_PROC(_security_pledge, OID_AUTO, learning_data,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, 0, /* TODO args ??? */
    sysctl_pledge_learning_data, "S,pledge_learning_entry_t",
    "Retrieve the learning data entries");

static counter_u64_t learning_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, learning_count,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLFLAG_RD,
    &learning_count, "Amount of recorded learning entries (for all CPUs)");

static counter_u64_t violation_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, violations,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLFLAG_RW | CTLFLAG_SECURE,
    &violation_count, "# of policy violations (enforced+learning)");

static counter_u64_t kill_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, kills,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLFLAG_RW | CTLFLAG_SECURE,
    &kill_count, "# of policy violations resulting in process kill");

static counter_u64_t softfail_count = NULL;
SYSCTL_COUNTER_U64(_security_pledge, OID_AUTO, softfails,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLFLAG_RW | CTLFLAG_SECURE,
    &softfail_count, "# of policy violations resulting in soft-fail");

/* TODO are proc nodes with CTLFLAG_SECURE generally accessible to
 * all users in the system? */
SYSCTL_BOOL(_security_pledge, OID_AUTO, enforcing,
#ifdef CTLFLAG_ROOTONLY
    CTLFLAG_ROOTONLY |
#endif
    CTLFLAG_RW | CTLFLAG_SECURE | CTLFLAG_RWTUN,
    &pledge_enforcing, 0,
    "enforce pledge violations (0: off, 1: enforcing)");

SYSCTL_PROC(_security_pledge, OID_AUTO, flags,
    CTLTYPE_U64 | CTLFLAG_WR | CTLFLAG_ANYBODY
    | CTLFLAG_PRISON | CTLFLAG_CAPWR | CTLFLAG_CAPRD | CTLFLAG_MPSAFE,
    NULL, 0, /* arg1, arg2 */
    sysctl_pledge_flags, "S,uint64_t", /* function, format*/
    "Reduce pledge flags for the calling thread");



/*
 * sysctl proc node for applying a new pledge mask to the calling thread.
 * The supplied mask is AND'ed with the thread's current mask, permitting
 * only reductions.
 */
static int
sysctl_pledge_flags(SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	uint64_t new_flags = req->td->td_pledge;

	error = sysctl_handle_64(oidp, &new_flags, 0, req);

	if (!error && req->newptr) {
		kern_pledge(req->td, new_flags);
	}

	return error;
}

/*
 * Learning mode
 * pledge_learning_init() - allocate table
 * pledge_learning_hash() - hash (fsid,inode) tuple to int
 * pledge_learning_insert() - update entry with used/violated flags
 * pledge_learning_record() - find (fsid,inode) and insert if learning enabled
 */

static MALLOC_DEFINE(M_PLEDGE_LEARNING, "pledge learning data",
    "pledge(8) learning mode data points.");

/*
 * Initialize learning mode memory structures
 */
static void
pledge_learning_init(const void *_unused)
{
	violation_count = counter_u64_alloc(M_WAITOK);
	learning_count = counter_u64_alloc(M_WAITOK);
	kill_count = counter_u64_alloc(M_WAITOK);
	softfail_count = counter_u64_alloc(M_WAITOK);

	/*
	 * These are small; we INIT them regardless of learning==1
	 * to avoid the headache of having to check for initialization later on:
	 */
	u_int cpu = 0;
	CPU_FOREACH(cpu) {
		rm_init(DPCPU_ID_PTR(cpu, learning_rm_lock),
			"security.pledge.learning");
		RB_INIT(DPCPU_ID_PTR(cpu, learning_tree));
	}
}

/*
 * Records the utilized and violated pledge privileges for a given executable
 * as identified by (fsid,inode) tuple.
 */
static inline void
pledge_learning_insert(const struct thread*thread,
    const dev_t fsid, const ino_t inode,
    const uint64_t used_mask, const uint64_t violated_mask){

	SDT_PROBE7(pledge, learning, insert, masks,
	   thread->td_proc->p_pid, fsid, inode, thread->td_sa.code,
	    thread->td_pledge, violated_mask, used_mask);

	/* Skip if learning mode is disabled: */
	if (!pledge_learning)
		return;

	u_int tree_idx = curcpu;
	struct rmlock * const rm = DPCPU_ID_PTR(tree_idx, learning_rm_lock);
	struct rm_priotracker rm_tracker = { 0 };
	rm_rlock(rm, &rm_tracker);
	learning_tree_t *tree = DPCPU_ID_PTR(tree_idx, learning_tree);

	/* Allocate member on the stack used to find existing entry
	 * with this inode/fsid combination. If there isn't one,
	 * we will need to copy this data to a proper allocation
	 * before inserting.
	 */
	pledge_splay_t stack_el = {
		.inode = inode,
		.fs_id = fsid,
		/* zero-initialize the remaining members
		 * since we may later want to add it to the tree */
		0
	};

	/* check if we already have an entry */
	pledge_splay_t *el =
	    learning_tree_RB_FIND(tree, &stack_el);

	if (el) {
		el->used |= used_mask;
		el->violated |= violated_mask;
		el->possessed |= thread->td_pledge;

		rm_runlock(rm, &rm_tracker);

		return;
	}

	/* the executable did not already have an entry,
	   so we need to add one. */

	/* drop lock so we can malloc our new entry: */
	rm_runlock(rm, &rm_tracker);
	el = malloc(sizeof(stack_el),
	    M_PLEDGE_LEARNING, M_WAITOK);
	memcpy(el, &stack_el, sizeof(stack_el));

	rm_wlock(rm);

	pledge_splay_t * const inserted = learning_tree_RB_INSERT(tree, el);
	if (inserted) {
		/* while we were busy malloc'ing,
		 * we were preempted, and the same
		 * element was inserted into this tree.
		 * use that instead of the newly malloc'ed entry that did not
		 * make it into the tree:
		 */
		free(el, M_PLEDGE_LEARNING);
		el = inserted;
	} else {
		counter_u64_add(learning_count, 1);
	}

	el->used |= used_mask;
	el->violated |= violated_mask;
	el->possessed |= thread->td_pledge;

	rm_wunlock(rm);
}

/*
 * TODO. ideally we would not call VOP_GETATTR on *each* call to this...
 */
static inline void
pledge_learning_record(const struct thread *thread,
    const uint64_t used_mask,
    const uint64_t violated_mask)
{
	if (!pledge_learning) { /* check sysctl */
		return;
	}

	int err = 0;

	/* seems like this would be a great place to have a LRU cache
	   of vnode/inode to avoid having to take all these locks...*/

	/* pointer to vnode for thread's executable */
	/* locks: thread->td_proc (*) not yet protected
	 * td_proc->p_textvp (b) created at fork, never changes
	 */
	struct vnode * const exec_vnode = thread->td_proc->p_textvp;

	/* assert that we have a vnode, and that it is a regular file: */
	if (!exec_vnode || VREG != exec_vnode->v_type) {
		/* in this case should probably have an ERROR entry
		 * that contains the appropriate mask for things we
		 * failed to look up? */
		goto proc_unlock_and_return;
	}

	struct vattr exec_vattr = {0};
	err = VOP_GETATTR(exec_vnode, &exec_vattr, NOCRED);
	if (err) {
		goto proc_unlock_and_return;
	}

	const dev_t exec_fsid = exec_vattr.va_fsid;
	const ino_t exec_fileid = exec_vattr.va_fileid;
	_Static_assert(sizeof(exec_vattr.va_fileid) == sizeof(ino_t), "va_fileid<>ino_t");
	/* TODO consider grouping by exec_vattr.va_filerev also?
	 * for ZFS that seems like it contains txgid ?
	 * https://github.com/freebsd/freebsd/blob/45d716be60e3806a85a0822cec12b8ce2321003b/sys/cddl/contrib/opensolaris/uts/common/fs/zfs/zfs_vnops.c#L2668
	 * Alternatively we could do something like track modification time
	 * and clear the recorded flags upon modification (or just store
	 * duplicate entries where userland will have to decide with outdated
	 * recordings. Finally we could let that be up to the user through
	 * sysctl configuration. )
	 */

	pledge_learning_insert(thread, exec_fsid, exec_fileid,
	    used_mask, violated_mask);

	return; /* no fall-through */

proc_unlock_and_return:
	printf("pledge TODO proc_unlock_and_return: not good.\n");
	return;
}


/*
 * sysctl proc node that copies (to userspace) the learning data.
 */
static int
sysctl_pledge_learning_data(SYSCTL_HANDLER_ARGS)
{
	if (req->newptr || req->newlen) {
		printf("pledge: trying to set learning data, "
		    "this sysctl should be RD only\n");
		return EINVAL;
	}

	/* TODO it's unfortunate that only sum(dpcpu counter array) is exposed;
	 * being able to retrieve max(dpcpu counter array) would be useful. */
	const uint64_t entries_num_max = counter_u64_fetch(learning_count);
	const uint64_t entries_bytes_max =
	    entries_num_max * sizeof(pledge_learning_entry_t);

	if (!req->oldptr) {
		/* userspace did not provide pointer; only interested in space
		 * required to dump data. We estimate: */
		return SYSCTL_OUT(req, NULL, entries_bytes_max);
	}

	if (!req->oldlen) {
		/* TODO userland asked for 0 bytes, having a special case
		 * in kernel-land for that seems a bit stupid */
		return SYSCTL_OUT(req, NULL, 0);
	}

	const size_t idx_max = req->oldlen / sizeof(pledge_learning_entry_t);

	if (idx_max * sizeof(pledge_learning_entry_t) != req->oldlen) {
		/* userland should ask for at least one entry and give
		 * us exactly the space we need to store them: */
		printf("pledge: learning_data %zd EINVAL TODO\n", req->oldlen);
		return (EINVAL);
	}

	/* Allocate contiguous buffer so we can attempt one big copyout().
	 * User can potentially request a very large amount of memory, so we
	 * allow the malloc to fail.
	 * One big buffer seemed better than doing copyouts for each element,
	 * but it scales poorly with a large number of CPUs.
	 * Could also consider a copyout per CPU node, or to merge the data in-kernel.
	 * TODO also consider returning EINVAL if
	 * req->oldlen > entries_num_max + (n) * mp_ncpus
	 * where (n) is some sensible constant (since we don't have a
	 * synced upper bound to compare against).
	 * It seemed unclean, so I did not include that here. */
	pledge_learning_entry_t * const entry_arr =
	    malloc(req->oldlen, M_PLEDGE_LEARNING, M_ZERO | M_NOWAIT);

	/* If system is low on memory, it's a bad time to dump learning data: */
	if (!entry_arr) {
		printf("kern:pledge:not enough memory for ldata\n");
		return (ENOSPC);
	}

	size_t idx = 0;
	int err = 0;

	u_int cpu = 0;
	CPU_FOREACH(cpu) {
		if (idx >= idx_max) break;
		struct rmlock * const rm = DPCPU_ID_PTR(cpu, learning_rm_lock);
		struct rm_priotracker rm_tracker = { 0 };
		rm_rlock(rm, &rm_tracker);
		learning_tree_t * const tree = DPCPU_ID_PTR(cpu, learning_tree);
		pledge_splay_t *el = NULL;
		RB_FOREACH(el, learning_tree, tree) {
			if (idx >= idx_max) break;
			/* printf("pledge el: inode %lu fs_id: %lu"
			    " used:0x%0lx viol:0x%0lx pos:0x%0lx\n",
			    el->inode, el->fs_id,
			    el->used, el->violated, el->possessed); */
			pledge_learning_entry_t * const user_entry =
			    entry_arr + idx;
			user_entry->is_populated = true;
			user_entry->used_flags = el->used;
			user_entry->violated_flags = el->violated;
			user_entry->possessed = el->possessed;
			user_entry->inode = el->inode;
			user_entry->fsid = el->fs_id;
			idx++;
		}
		rm_runlock(rm, &rm_tracker);
	}

	err = SYSCTL_OUT(req, entry_arr, idx*sizeof(pledge_learning_entry_t));
	if (err) {
		printf("pledge:SYSCTL_OUT failed err %d idx %zd\n", err, idx);
	}

	free(entry_arr, M_PLEDGE_LEARNING);

	return (err);
}


/*
 * Generic function to handle a permission check.
 * By default it checks if ONE of the flags is set, this behaviour can be
 * changed to compare against all the flags by OR'ing with PLEDGE_AND.
 * Returns ENOTCAPABLE or exits() the process, this function MAY NOT RETURN.
 */
int
pledge_check_bitmap(struct thread * const thread, const uint64_t flags)
{

	/* Assume we need to match ALL the flags: */
	uint64_t violated =
	    (flags & PLEDGE_WILDCARD)
	    & (~(thread->td_pledge));

	/* used_mask is the intersection between required and possessed: */
	// TODO atm we over-report a little bit since if AND is not set
	// we really only need one of them, not all of the target flags.
	// Potential solution would be to just pick the lowest.
	uint64_t used_mask =
	    (flags & PLEDGE_WILDCARD & thread->td_pledge);

	/* Retain (violated) if one or more constraints are met:
	 * 1) the PLEDGE_AND bit is set in (flags)
	 * 2) the permission intersection of (flags) and (td_pledge) is empty
	 * Conversely this clears (violated) by multiplying it with 0
	 * when !PLEDGE_AND && at least one required permission is possessed.
	 */
	violated *=
	    !!( (PLEDGE_AND & flags)
		| !used_mask);

	/* Record the lacking permissions.
	 * When there is a violation, and the PLEDGE_AND flag was NOT set
	 * record this bit. This signals to userspace that not all the
	 * "violated" flags may actually be required, since a subset
	 * would have sufficed.
	 * TODO flipping the logic here and having PLEDGE_OR would make this cleaner, but make the table uglier.
	 * TODO document this in the manpages
	 * TODO document in pledgectl
	 */
	if (violated && !( PLEDGE_AND & flags)) {
		pledge_learning_record(thread, used_mask,
		    PLEDGE_AND | violated);
	} else {
		pledge_learning_record(thread, used_mask, violated);
	}

	if (violated & PLEDGE_WILDCARD)
		counter_u64_add(violation_count, 1);

	/* Fall through if the sysctl for enforcement is not enabled:*/
	if (violated && pledge_enforcing) {
		/* return a permission error if the wanted syscall_no is not
		 * permitted by the thread's current pledge bitmap: */

		tprintf(thread->td_proc, 0,
		    "pledge: %s pid %d syscall %d due to td_pledge=0x%0lx "
		    "; relevant=0x%0lx\n",
		    ((thread->td_pledge & PLEDGE_SOFTFAIL) ?
			"soft-failing" : "crashing"),
		    thread->td_proc->p_pid, thread->td_sa.code,
		    thread->td_pledge, flags);

		if (0 == (thread->td_pledge & PLEDGE_SOFTFAIL)) {
			/* crash process:
			 * 2nd arg is exit code
			 * 3rd arg is signo
			 * TODO maybe call sys_abort2 instead to produce
			 * inspectable core? */
			counter_u64_add(kill_count, 1);
			exit1(thread, 0, SIGKILL);
			// TODO misunderstood exit1?
			counter_u64_add(kill_count, 1337);
		}

		counter_u64_add(softfail_count, 1);
		return (ENOTCAPABLE);
	}

	return 0;
}

/*
 * Apply intersection of new permission mask and the current mask.
 * Always succeeds.
 */
int
kern_pledge(struct thread *td, const uint64_t mask)
{
	/* Would probably be a good place for a DTrace probe.*/
	/* TODO do we need to lock td? */
	SDT_PROBE5(pledge, kern, kern_pledge, masks,
	    td->td_proc->p_pid, 0, 0, td->td_pledge, mask);
	td->td_pledge &= (mask & ~PLEDGE_AND);
	return 0;
}

/*
 * Look up pledge bitmask for binary stored in the "system:pledge" extattr
 * (using the context of a userspace thread), and if it exists
 * applying the associated mask to the thread's current pledge mask.
 * Returns 0 if nd does not have the "pledge" extattr.
 */
int
pledge_apply_extattr(struct thread *td, struct vnode *ni_vp)
{
	int err = 0;

	uint64_t retrieved_mask = PLEDGE_NONE;

	/* initialize size to non-zero to verify it got changed later: */
	size_t attr_total = ~0ULL;
	struct uio uio = {0};
	struct iovec iov = {0};

	/*
	 * Read the system:pledge extattr on the file in question.
	 */

	iov.iov_base = &retrieved_mask;
	iov.iov_len = sizeof(retrieved_mask);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_rw = UIO_READ;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_td = td;
	uio.uio_resid = sizeof(retrieved_mask);

	err = VOP_GETEXTATTR(ni_vp, EXTATTR_NAMESPACE_SYSTEM, "pledge",
	    &uio, &attr_total, NOCRED, td);


	/* TODO maybe this should be EXTATTR_NAMESPACE_USER to permit
	   people to pledge their own binaries */

	/* TODO I guess we need to bypass read permissions iff (td->ucred) has
	 * execute permission to the binary seeing as execution has gotten
	 * this far, we assume this is the case.
	 * Using td->td_ucred resulted in EPERM errors.
	 * Need to evaluate NOCRED vs td->td_ucred, also in other VOP_ ops
	 * in hbsd_pledge.c
	 */

	if (ENOATTR == err || EOPNOTSUPP == err) {
		/* it doesn't have a "pledge" extattr: */
		return 0;
	} else if (err) {
		printf("pledge_getmask_extattr: VOP_GETEXTATTR on  vnode %p "
		    "for attribute system:'pledge' failed with error (%d)\n",
		    ni_vp, err);
		return 1;
	} else if (sizeof(retrieved_mask) == attr_total) {
		/*
		 * TODO excellent place for a DTrace probe
		 */
		printf("pledge_getmask_extattr: vnode %p pledgemask 0x%lx\n",
		    ni_vp, retrieved_mask);
		return (kern_pledge(td, retrieved_mask));
	}
	else {
		/*
		 * If there's more data in here, something is wrong.
		 */
		tprintf(td->td_proc, 0, "pledge_getmask_extattr: "
		    "size of system.pledge extattr is %zd, expected == %zd\n",
		    attr_total, sizeof(retrieved_mask));
		return 1;
	}
}

/*
 * Validate open() access.
 * May not return, so care should be taken to free structures prior to calling.
 */
int inline
pledge_openat(struct thread *thread, const int fd, const char *path,
    const int flags, const int mode)
{

	uint64_t required_mask = PLEDGE_AND | PLEDGE_RPATH | PLEDGE_WPATH
	    | PLEDGE_CPATH | PLEDGE_FLOCK;

	/* TODO this would probably be a good point for path validation
	 * and whitelisting of /dev/null, /dev/urandom, etc.
	 * it would however feel better to check major/minor dev number
	 * to avoid problems with symlinks and whathaveyou.
	 */

	/* determine required capabilities depending on the open() flags:*/

	if (0 == (FFLAGS(flags) & FREAD))
		required_mask ^= PLEDGE_RPATH;

	if (0 == (FFLAGS(flags) & (FWRITE | FAPPEND)))
		required_mask ^= PLEDGE_WPATH;

	if (0 == (flags & O_CREAT)) {
		required_mask ^= PLEDGE_CPATH;
	}

	if (0 == (flags & (O_SHLOCK | O_EXLOCK)))
		required_mask ^= PLEDGE_FLOCK;

	if (PLEDGE_WILDCARD != (PLEDGE_WILDCARD & thread->td_pledge)) {
		/* TODO consider DTrace probe
		   printf("pledge: openat: flags:0x%0x vs req:0x%0lx\n",
		    flags, required_mask);
		*/
	}

	return (pledge_check_bitmap(thread, required_mask));
}

/*
 * This map is used in pledge_syscall() to determine which pledge flags are
 * relevant to determine access to a given syscall.
 * The syscall is allowed if ONE OR MORE flags match the thread's bitmap.
 *
 * The syscalls we do not filter using pledge are permitted by
 * initializing the entry in this table to PLEDGE_WILDCARD.
 *
 * The rationale for listing all of the system calls here is the philosophy
 * that even though it requires more maintenance, it is better to deny an
 * attempt to call an unhandled system call than permitting it.
 *
 * NOTE that there is a special case in that function that grants access if
 * pledge is turned off for that thread (when it is PLEDGE_WILDCARD), which is
 * the default defined in sys/kern/init_main.c
 *
 * These are listed in numerical, ascending order (see sys/sys/syscalls.h):
 */
static const
uint64_t pledge_permission_map[SYS_MAXSYSCALL] = {
	/* 0: */
	[SYS_syscall]	= PLEDGE_NONE, // TODO
	[SYS_exit]	= PLEDGE_NONE,
	[SYS_fork]	= PLEDGE_PROC,
	[SYS_read]	= PLEDGE_STDIO,
	[SYS_write]	= PLEDGE_STDIO,
	[SYS_open]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH,
	[SYS_close]	= PLEDGE_STDIO,
	[SYS_wait4]	= PLEDGE_PROC,
	[SYS_link]	= PLEDGE_CPATH,
	/* 10: */
	[SYS_unlink]	= PLEDGE_CPATH,
	[SYS_chdir]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_RPATH,
	[SYS_fchdir]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_RPATH,
#ifdef SYS_freebsd11_mknod
	[SYS_freebsd11_mknod]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#else
	[SYS_mknod]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#endif
	[SYS_chmod]	= PLEDGE_FATTR,
	[SYS_chown]	= PLEDGE_AND | PLEDGE_CHOWN | PLEDGE_CPATH, // chown
	[SYS_break]	= PLEDGE_STDIO,
	/* 20: */
	[SYS_getpid]	= PLEDGE_NONE,
	[SYS_mount]	= PLEDGE_DEVICE,
	[SYS_unmount]	= PLEDGE_DEVICE,
	[SYS_setuid]	= PLEDGE_ID,
	[SYS_getuid]	= PLEDGE_STDIO,
	[SYS_geteuid]	= PLEDGE_STDIO,
	[SYS_ptrace]	= PLEDGE_PROC,
	[SYS_recvmsg]	= PLEDGE_STDIO,
	[SYS_sendmsg]	= PLEDGE_STDIO,
	[SYS_recvfrom]	= PLEDGE_STDIO,
	/* 30: */
	[SYS_accept]	= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getpeername] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_getsockname] = PLEDGE_INET | PLEDGE_UNIX,
	[SYS_access]	= PLEDGE_RPATH,
	[SYS_chflags]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS_fchflags]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS_sync]	= PLEDGE_STDIO,
	[SYS_kill]	= PLEDGE_PROC,
	[SYS_getppid]	= PLEDGE_STDIO,
	[SYS_dup]	= PLEDGE_STDIO,
	[SYS_freebsd10_pipe] = PLEDGE_STDIO,
	[SYS_getegid]	= PLEDGE_STDIO,
	[SYS_profil]	= PLEDGE_STDIO,
	[SYS_ktrace]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_PROC,
	[SYS_getgid]	= PLEDGE_STDIO,
	[SYS_getlogin]	= PLEDGE_STDIO,
	/* 50: */
	[SYS_setlogin]	= PLEDGE_ID,
	[SYS_acct]	= PLEDGE_PROC,
	[SYS_sigaltstack] = PLEDGE_STDIO,
	[SYS_ioctl]	= PLEDGE_STDIO,
	[SYS_reboot]	= PLEDGE_PROC,
	[SYS_revoke]	= PLEDGE_STDIO,
	[SYS_symlink]	= PLEDGE_CPATH,
	[SYS_readlink]	= PLEDGE_RPATH,
	[SYS_execve]	= PLEDGE_AND | PLEDGE_EXEC | PLEDGE_PROC,
	/* 60: */
	[SYS_umask]	= PLEDGE_STDIO,
	[SYS_chroot]	= PLEDGE_STDIO,
	[SYS_msync]	= PLEDGE_STDIO,
	[SYS_vfork]	= PLEDGE_PROC,
	[SYS_sbrk]	= PLEDGE_STDIO,
	/* 70: */
	[SYS_sstk]	= PLEDGE_STDIO,
#ifndef SYS_vadvise
#define SYS_vadvise SYS_freebsd11_vadvise
#endif
	[SYS_vadvise]	= PLEDGE_STDIO,
	[SYS_munmap]	= PLEDGE_STDIO,
	[SYS_mprotect]	= PLEDGE_STDIO,
	[SYS_madvise]	= PLEDGE_STDIO,
	[SYS_mincore]	= PLEDGE_STDIO,
	[SYS_getgroups]	= PLEDGE_STDIO,
	/* 80: */
	[SYS_setgroups]	= PLEDGE_ID,
	[SYS_getpgrp]		= PLEDGE_STDIO,
	[SYS_setpgid]		= PLEDGE_STDIO,
	[SYS_setitimer]	= PLEDGE_STDIO,
	[SYS_swapon]		= PLEDGE_DEVICE,
	[SYS_getitimer]	= PLEDGE_STDIO,
	[SYS_getdtablesize]	= PLEDGE_DEVICE, // TODO
	/* 90: */
	[SYS_dup2]	= PLEDGE_STDIO,
	[SYS_fcntl]	= PLEDGE_STDIO,
	[SYS_select]	= PLEDGE_STDIO,
	[SYS_fsync]	= PLEDGE_STDIO,
	[SYS_setpriority] = PLEDGE_STDIO,
	[SYS_socket]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	[SYS_connect]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	/* 100: */
	[SYS_getpriority]	= PLEDGE_STDIO,
	[SYS_bind]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX,
	[SYS_setsockopt]	= PLEDGE_DNS | PLEDGE_INET | PLEDGE_UNIX, // TODO
	[SYS_listen]	= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_gettimeofday]	= PLEDGE_STDIO,
	[SYS_getrusage]	= PLEDGE_STDIO,
	[SYS_getsockopt]	= PLEDGE_STDIO,
	/* 120: */
	[SYS_readv]	= PLEDGE_STDIO,
	[SYS_writev]	= PLEDGE_STDIO,
	[SYS_settimeofday]	= PLEDGE_SETTIME,
	[SYS_fchown]	= PLEDGE_CHOWN,
	[SYS_fchmod]	= PLEDGE_FATTR,
	[SYS_setreuid]	= PLEDGE_ID,
	[SYS_setregid]	= PLEDGE_ID,
	[SYS_rename]	= PLEDGE_CPATH,
	[SYS_flock]	= PLEDGE_FLOCK,
	[SYS_mkfifo]	= PLEDGE_CPATH,
	[SYS_sendto]	= PLEDGE_STDIO,
	[SYS_shutdown]	= PLEDGE_PROC,
	[SYS_socketpair]	= PLEDGE_STDIO,
	[SYS_mkdir]	= PLEDGE_CPATH,
	[SYS_rmdir]	= PLEDGE_CPATH,
	[SYS_utimes]	= PLEDGE_FATTR,
	/* 140: */
	[SYS_adjtime]	= PLEDGE_SETTIME,
	[SYS_setsid]	= PLEDGE_STDIO,
	[SYS_quotactl]	= PLEDGE_STDIO, /* TODO */
	[SYS_nlm_syscall] = PLEDGE_STDIO, /* TODO */
	[SYS_nfssvc]	= PLEDGE_STDIO,
	/* 160: */
	[SYS_lgetfh]	= PLEDGE_WPATH | PLEDGE_RPATH, /* TODO */
	[SYS_getfh]	= PLEDGE_WPATH | PLEDGE_RPATH, /* TODO */
	[SYS_sysarch]	= PLEDGE_STDIO, /* TODO */
	[SYS_rtprio]	= PLEDGE_STDIO,
	[SYS_semsys]	= PLEDGE_STDIO,
	/* 170: */
	[SYS_msgsys]	= PLEDGE_STDIO, /* TODO */
	[SYS_shmsys]	= PLEDGE_STDIO,
	[SYS_setfib]	= PLEDGE_ROUTE,
	[SYS_ntp_adjtime] = PLEDGE_STDIO,
	[SYS_setgid]	= PLEDGE_ID,
	[SYS_setegid]	= PLEDGE_ID,
	[SYS_seteuid]	= PLEDGE_ID,
	[SYS_freebsd11_stat]	= PLEDGE_RPATH,
#ifdef SYS_freebsd11_fstat
	[SYS_freebsd11_fstat]	= PLEDGE_STDIO,
#endif
	/* 190: */
	[SYS_freebsd11_lstat]	= PLEDGE_RPATH,
	[SYS_pathconf]	= PLEDGE_STDIO, // NONE?
	[SYS_fpathconf] = PLEDGE_STDIO,
	/* TODO what happened to 193? */
	[SYS_getrlimit] = PLEDGE_STDIO,
	[SYS_setrlimit] = PLEDGE_STDIO,
	[SYS_freebsd11_getdirentries] = PLEDGE_STDIO,
	[SYS___syscall] = PLEDGE_STDIO, // TODO does this allow bypass?
	[SYS___sysctl]	= PLEDGE_STDIO, // TODO
	[SYS_mlock]	= PLEDGE_STDIO,
	[SYS_munlock]	= PLEDGE_STDIO,
	[SYS_undelete]	= PLEDGE_CPATH, // TODO
	[SYS_futimes]	= PLEDGE_FATTR,
	[SYS_getpgid]	= PLEDGE_STDIO,
	[SYS_poll]	= PLEDGE_STDIO,
	/* 220: */
	[SYS_freebsd7___semctl] = PLEDGE_STDIO,
	[SYS_semget]	= PLEDGE_UNIX,
	[SYS_semop]	= PLEDGE_STDIO,
	[SYS_freebsd7_msgctl] = PLEDGE_STDIO,
	[SYS_msgget]	= PLEDGE_STDIO,
	[SYS_msgsnd]	= PLEDGE_STDIO,
	[SYS_msgrcv]	= PLEDGE_STDIO,
	[SYS_shmat]	= PLEDGE_STDIO,
	[SYS_freebsd7_shmctl]	= PLEDGE_STDIO,
	/* 230: */
	[SYS_shmdt]	= PLEDGE_STDIO, /* TODO */
	[SYS_shmget]	= PLEDGE_STDIO,
	[SYS_clock_gettime]	= PLEDGE_STDIO,
	[SYS_clock_settime]	= PLEDGE_SETTIME,
	[SYS_clock_getres]	= PLEDGE_STDIO,
	[SYS_ktimer_create]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_UNIX,
	[SYS_ktimer_delete]	= PLEDGE_STDIO,
	[SYS_ktimer_settime]	= PLEDGE_STDIO,
	[SYS_ktimer_gettime]	= PLEDGE_STDIO,
	[SYS_ktimer_getoverrun]	= PLEDGE_STDIO,
	/* 240: */
	[SYS_nanosleep]		= PLEDGE_NONE,
	[SYS_ffclock_getcounter]	= PLEDGE_STDIO,
	[SYS_ffclock_setestimate]	= PLEDGE_STDIO,
	[SYS_ffclock_getestimate]	= PLEDGE_STDIO,
	[SYS_clock_nanosleep]		= PLEDGE_NONE,
	[SYS_clock_getcpuclockid2]	= PLEDGE_STDIO,
	[SYS_ntp_gettime]		= PLEDGE_STDIO,
	/* 250: */
	[SYS_minherit]	= PLEDGE_STDIO,
	[SYS_rfork]	= PLEDGE_PROC | PLEDGE_STDIO,
	[SYS_issetugid]	= PLEDGE_STDIO,
	[SYS_lchown]	= PLEDGE_CHOWN, // chown
	[SYS_aio_read]	= PLEDGE_STDIO, // TODO
	[SYS_aio_write]	= PLEDGE_STDIO, // TODO
	[SYS_lio_listio]	= PLEDGE_STDIO, // TODO
	/* 272 */
	[SYS_freebsd11_getdents]	= PLEDGE_RPATH,
	[SYS_lchmod]	= PLEDGE_FATTR,
#ifdef SYS_netbsd_lchown
	[SYS_netbsd_lchown]	= PLEDGE_CHOWN, // chown
#endif
	[SYS_lutimes]	= PLEDGE_FATTR,
#ifdef SYS_netbsd_msync
	[SYS_netbsd_msync]	= PLEDGE_STDIO, // TODO
#endif
	[SYS_freebsd11_nstat]	= PLEDGE_STDIO,
	[SYS_freebsd11_nfstat]	= PLEDGE_STDIO, // TODO
	/* 280: */
	[SYS_freebsd11_nlstat]	= PLEDGE_STDIO,
	[SYS_preadv]	= PLEDGE_STDIO,
	/* 290: */
	[SYS_pwritev]	= PLEDGE_STDIO,
	[SYS_fhopen]	= PLEDGE_RPATH | PLEDGE_WPATH,
	[SYS_freebsd11_fhstat]	= PLEDGE_RPATH | PLEDGE_WPATH,
	/* 300: */
	[SYS_modnext]	= PLEDGE_KLD,
	[SYS_modstat]	= PLEDGE_KLD,
	[SYS_modfnext]	= PLEDGE_KLD,
	[SYS_modfind]	= PLEDGE_KLD,
	[SYS_kldload]	= PLEDGE_AND | PLEDGE_EXEC | PLEDGE_KLD | PLEDGE_RPATH,
	[SYS_kldunload]	= PLEDGE_KLD,
	[SYS_kldfind]	= PLEDGE_KLD,
	[SYS_kldnext]	= PLEDGE_KLD,
	[SYS_kldstat]	= PLEDGE_KLD,
	[SYS_kldfirstmod]	= PLEDGE_KLD,
	/* 310: */
	[SYS_getsid]	= PLEDGE_STDIO,
	[SYS_setresuid]	= PLEDGE_ID,
	[SYS_setresgid]	= PLEDGE_ID,
	[SYS_aio_return]	= PLEDGE_STDIO,
	[SYS_aio_suspend]	= PLEDGE_STDIO,
	[SYS_aio_cancel]	= PLEDGE_STDIO,
	[SYS_aio_error]	= PLEDGE_STDIO,
	[SYS_yield]	= PLEDGE_NONE,
	[SYS_mlockall]	= PLEDGE_STDIO,
	[SYS_munlockall]	= PLEDGE_STDIO,
	[SYS___getcwd]	= PLEDGE_STDIO,
	[SYS_sched_setparam]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_getparam]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_setscheduler]= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	/* 330: */
	[SYS_sched_getscheduler]= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_yield]	= PLEDGE_NONE,
	[SYS_sched_get_priority_max]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_get_priority_min]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_sched_rr_get_interval]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_utrace]	= PLEDGE_KLD,
	[SYS_kldsym]	= PLEDGE_KLD,
	[SYS_jail]	= PLEDGE_STDIO,
	[SYS_nnpfs_syscall]	= PLEDGE_KLD,
	/* 340: */
	[SYS_sigprocmask]	= PLEDGE_STDIO,
	[SYS_sigsuspend]	= PLEDGE_STDIO,
	[SYS_sigpending]	= PLEDGE_STDIO,
	[SYS_sigtimedwait]	= PLEDGE_STDIO,
	[SYS_sigwaitinfo]	= PLEDGE_STDIO,
	[SYS___acl_get_file]	= PLEDGE_STDIO,
	[SYS___acl_set_file]	= PLEDGE_STDIO,
	[SYS___acl_get_fd]	= PLEDGE_STDIO,
	/* 350: */
	[SYS___acl_set_fd]	= PLEDGE_STDIO,
	[SYS___acl_delete_file]	= PLEDGE_STDIO,
	[SYS___acl_delete_fd]	= PLEDGE_STDIO,
	[SYS___acl_aclcheck_file]	= PLEDGE_STDIO,
	[SYS___acl_aclcheck_fd]	= PLEDGE_STDIO,
	[SYS_extattrctl]	= PLEDGE_STDIO,
	[SYS_extattr_set_file]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_FATTR,
	[SYS_extattr_get_file]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_RPATH,
	[SYS_extattr_delete_file]	= PLEDGE_CPATH,
	[SYS_aio_waitcomplete]	= PLEDGE_STDIO,
	/* 360: */
	[SYS_getresuid]	= PLEDGE_STDIO,
	[SYS_getresgid]	= PLEDGE_STDIO,
	[SYS_kqueue]	= PLEDGE_STDIO, /* TODO */
	[SYS_freebsd11_kevent]	= PLEDGE_STDIO, /* 363, TODO */
	[SYS_extattr_set_fd]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_WPATH,
	[SYS_extattr_get_fd]	= PLEDGE_RPATH,
	[SYS_extattr_delete_fd]	= PLEDGE_AND | PLEDGE_FATTR | PLEDGE_CPATH,
	[SYS___setugid]	= PLEDGE_ID,
	[SYS_eaccess]	= PLEDGE_STDIO,
	[SYS_afs3_syscall]	= PLEDGE_STDIO, /* TODO */
	[SYS_nmount]	= PLEDGE_DEVICE,
	[SYS___mac_get_proc]	= PLEDGE_STDIO,
	[SYS___mac_set_proc]	= PLEDGE_STDIO, /* TODO */
	[SYS___mac_get_fd]	= PLEDGE_STDIO,
	[SYS___mac_get_file]	= PLEDGE_STDIO,
	[SYS___mac_set_fd]	= PLEDGE_STDIO, /* TODO */
	[SYS___mac_set_file]	= PLEDGE_STDIO, /* TODO */
	/* 390: */
	[SYS_kenv]	= PLEDGE_STDIO,
	[SYS_lchflags]	= PLEDGE_FATTR,
	[SYS_uuidgen]	= PLEDGE_STDIO, // leaks mac address so...
	[SYS_sendfile]	= PLEDGE_STDIO,
	[SYS_mac_syscall]	= PLEDGE_STDIO, /* TODO */
	[SYS_freebsd11_getfsstat]	= PLEDGE_STDIO,
	[SYS_freebsd11_statfs]	= PLEDGE_STDIO,
	[SYS_freebsd11_fstatfs]	= PLEDGE_STDIO,
	[SYS_freebsd11_fhstatfs]	= PLEDGE_STDIO,
	/* 400: */
	[SYS_ksem_close]	= PLEDGE_STDIO,
	[SYS_ksem_post]	= PLEDGE_STDIO, /* TODO */
	[SYS_ksem_wait]	= PLEDGE_STDIO,
	[SYS_ksem_trywait]	= PLEDGE_STDIO,
	[SYS_ksem_init]	= PLEDGE_STDIO,
	[SYS_ksem_open]	= PLEDGE_STDIO,
	[SYS_ksem_unlink]	= PLEDGE_STDIO,
	[SYS_ksem_getvalue]	= PLEDGE_STDIO,
	[SYS_ksem_destroy]	= PLEDGE_STDIO,
	[SYS___mac_get_pid]	= PLEDGE_STDIO,
	/* 410: */
	[SYS___mac_get_link]	= PLEDGE_FATTR,
	[SYS___mac_set_link]	= PLEDGE_FATTR,
	[SYS_extattr_set_link]	= PLEDGE_CPATH,
	[SYS_extattr_get_link]	= PLEDGE_RPATH,
	[SYS_extattr_delete_link]	= PLEDGE_CPATH,
	[SYS___mac_execve]	= PLEDGE_FATTR, /* TODO */
	[SYS_sigaction]	= PLEDGE_STDIO,
	[SYS_sigreturn]	= PLEDGE_STDIO,
	[SYS_getcontext]	= PLEDGE_STDIO,
	[SYS_setcontext]	= PLEDGE_STDIO,
	[SYS_swapcontext]	= PLEDGE_STDIO,
	[SYS_swapoff]		= PLEDGE_STDIO,
	[SYS___acl_get_link]	= PLEDGE_FATTR,
	[SYS___acl_set_link]	= PLEDGE_FATTR,
	[SYS___acl_delete_link]	= PLEDGE_FATTR,
	[SYS___acl_aclcheck_link]	= PLEDGE_FATTR,
	[SYS_sigwait]	= PLEDGE_STDIO,
	/* 430: */
	[SYS_thr_create]	= PLEDGE_PROC, // TODO
	[SYS_thr_exit]	= PLEDGE_STDIO,
	[SYS_thr_self]	= PLEDGE_STDIO,
	[SYS_thr_kill]	= PLEDGE_STDIO,
	[SYS_jail_attach]	= PLEDGE_STDIO, // TODO
	[SYS_extattr_list_fd]	= PLEDGE_STDIO, /* TODO */
	[SYS_extattr_list_file]	= PLEDGE_STDIO,
	[SYS_extattr_list_link]	= PLEDGE_STDIO,
	[SYS_ksem_timedwait]	= PLEDGE_STDIO,
	[SYS_thr_suspend]	= PLEDGE_PROC,
	[SYS_thr_wake]	= PLEDGE_PROC,
	[SYS_kldunloadf]	= PLEDGE_KLD,
	[SYS_audit]	= PLEDGE_STDIO,
	[SYS_auditon]	= PLEDGE_STDIO,
	[SYS_getauid]	= PLEDGE_STDIO,
	[SYS_setauid]	= PLEDGE_ID,
	[SYS_getaudit]	= PLEDGE_STDIO,
	/* 450: */
	[SYS_setaudit]	= PLEDGE_STDIO,
	[SYS_getaudit_addr]	= PLEDGE_STDIO,
	[SYS_setaudit_addr]	= PLEDGE_STDIO,
	[SYS_auditctl]	= PLEDGE_AND | PLEDGE_WPATH | PLEDGE_DEVICE, /* TODO */
	[SYS__umtx_op]	= PLEDGE_STDIO,
	[SYS_thr_new]	= PLEDGE_STDIO,
	[SYS_sigqueue]	= PLEDGE_STDIO,
	[SYS_kmq_open]	= PLEDGE_STDIO,
	[SYS_kmq_setattr]	= PLEDGE_STDIO,
	[SYS_kmq_timedreceive]	= PLEDGE_STDIO,
	/* 460: */
	[SYS_kmq_timedsend]	= PLEDGE_STDIO,
	[SYS_kmq_notify]	= PLEDGE_STDIO,
	[SYS_kmq_unlink]	= PLEDGE_STDIO,
	[SYS_abort2]	= PLEDGE_STDIO,
	[SYS_thr_set_name]	= PLEDGE_STDIO,
	[SYS_aio_fsync]	= PLEDGE_STDIO,
	[SYS_rtprio_thread]	= PLEDGE_STDIO,
	[SYS_sctp_peeloff]	= PLEDGE_INET, /* TODO ... */
	[SYS_sctp_generic_sendmsg]	= PLEDGE_INET,
	[SYS_sctp_generic_sendmsg_iov]	= PLEDGE_INET,
	[SYS_sctp_generic_recvmsg]	= PLEDGE_INET,
	[SYS_pread]	= PLEDGE_STDIO,
	[SYS_pwrite]	= PLEDGE_STDIO,
	[SYS_mmap]	= PLEDGE_STDIO,
	[SYS_lseek]	= PLEDGE_STDIO, // TODO consider append-only?
	[SYS_truncate]	= PLEDGE_WPATH,
	/* 480: */
	[SYS_ftruncate]	= PLEDGE_WPATH,
	[SYS_thr_kill2]	= PLEDGE_STDIO,
#ifdef SYS_freebsd12_shm_open
	[SYS_freebsd12_shm_open] = PLEDGE_RPATH | PLEDGE_WPATH, /* TODO */
#elif SYS_shm_open
	[SYS_shm_open]	= PLEDGE_RPATH | PLEDGE_WPATH, /* TODO */
#endif
	[SYS_shm_unlink]	= PLEDGE_CPATH,
	[SYS_cpuset]	= PLEDGE_STDIO,
	[SYS_cpuset_setid]	= PLEDGE_STDIO,
	[SYS_cpuset_getid]	= PLEDGE_STDIO,
	[SYS_cpuset_getaffinity]	= PLEDGE_STDIO,
	[SYS_cpuset_setaffinity]	= PLEDGE_STDIO,
	[SYS_faccessat]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH,
	/* 490: */
	[SYS_fchmodat]	= PLEDGE_FATTR,
	[SYS_fchownat]	= PLEDGE_CHOWN, // chown
	[SYS_fexecve]	= PLEDGE_PROC, // TODO openbsd have PLEDGE_EXEC because they distinguish between fork an execve
#ifdef SYS_freebsd11_fstatat
	/* this is a bit ugly, we have a definition for
	 SYS_fstatat further below. would be nice to have
	 them in the same place. TODO */
	[SYS_freebsd11_fstatat]	= PLEDGE_RPATH, // TODO also STDIO
#endif
	[SYS_futimesat]	= PLEDGE_FATTR,
	[SYS_linkat]	= PLEDGE_CPATH,
	[SYS_mkdirat]	= PLEDGE_CPATH,
	[SYS_mkfifoat]	= PLEDGE_CPATH,
#ifdef SYS_freebsd11_mknodat
	[SYS_freebsd11_mknodat]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#else
	[SYS_mknodat]	= PLEDGE_AND | PLEDGE_CPATH | PLEDGE_DEVICE,
#endif
	[SYS_openat]	= PLEDGE_RPATH | PLEDGE_WPATH,
	/* 500: */
	[SYS_readlinkat]	= PLEDGE_RPATH | PLEDGE_WPATH | PLEDGE_CPATH, // TODO
	[SYS_renameat]	= PLEDGE_CPATH,
	[SYS_symlinkat]	= PLEDGE_CPATH,
	[SYS_unlinkat]	= PLEDGE_CPATH,
	[SYS_posix_openpt]	= PLEDGE_STDIO, // TODO pledge_TTY ?
	[SYS_gssd_syscall]	= PLEDGE_STDIO, /* TODO */
	[SYS_jail_get]	= PLEDGE_PROC, // TODO consider pledge flag for this
	[SYS_jail_set]	= PLEDGE_PROC,
	[SYS_jail_remove]	= PLEDGE_PROC,
	[SYS_closefrom]	= PLEDGE_STDIO,
	/* 510: */
	[SYS___semctl]	= PLEDGE_STDIO,
	[SYS_msgctl]	= PLEDGE_STDIO,
	[SYS_shmctl]	= PLEDGE_STDIO,
	[SYS_lpathconf]	= PLEDGE_STDIO, // TODO
	[SYS___cap_rights_get]	= PLEDGE_STDIO, // TODO?
	[SYS_cap_enter]	= PLEDGE_STDIO,
	[SYS_cap_getmode]	= PLEDGE_STDIO,
	[SYS_pdfork]	= PLEDGE_PROC,
	[SYS_pdkill]	= PLEDGE_PROC,
	/* 520: */
	[SYS_pdgetpid]	= PLEDGE_AND | PLEDGE_STDIO | PLEDGE_PROC,
	[SYS_pselect]	= PLEDGE_STDIO,
	[SYS_getloginclass]	= PLEDGE_STDIO,
	[SYS_setloginclass]	= PLEDGE_STDIO,
	[SYS_rctl_get_racct]	= PLEDGE_STDIO,
	[SYS_rctl_get_rules]	= PLEDGE_STDIO,
	[SYS_rctl_get_limits]	= PLEDGE_STDIO,
	[SYS_rctl_add_rule]	= PLEDGE_STDIO,
	[SYS_rctl_remove_rule]	= PLEDGE_STDIO,
	/* 530: */
	[SYS_posix_fallocate]	= PLEDGE_STDIO,
	[SYS_posix_fadvise]	= PLEDGE_STDIO,
	[SYS_wait6]		= PLEDGE_STDIO,
	[SYS_cap_rights_limit]	= PLEDGE_STDIO,
	[SYS_cap_ioctls_limit]	= PLEDGE_STDIO,
	[SYS_cap_ioctls_get]	= PLEDGE_STDIO,
	[SYS_cap_fcntls_limit]	= PLEDGE_STDIO,
	[SYS_cap_fcntls_get]	= PLEDGE_STDIO,
	[SYS_bindat]		= PLEDGE_UNIX,
	[SYS_connectat]	= PLEDGE_UNIX,
	/* 540: */
	[SYS_chflagsat]	= PLEDGE_FATTR,
	[SYS_accept4]		= PLEDGE_INET | PLEDGE_UNIX,
	[SYS_pipe2]		= PLEDGE_STDIO,
	[SYS_aio_mlock]	= PLEDGE_STDIO,
	[SYS_procctl]		= PLEDGE_PROC,
	[SYS_ppoll]		= PLEDGE_STDIO,
	[SYS_futimens]		= PLEDGE_FATTR,
	[SYS_utimensat]	= PLEDGE_FATTR,
	/* 550: */
	[SYS_fdatasync]	= PLEDGE_STDIO,
/* at this point twenty new syscalls were added (around 13-CURRENT).*/
#ifdef SYS_fstat
	[SYS_fstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fstatat
	[SYS_fstatat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fhstat
	[SYS_fhstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_getdirentries
	[SYS_getdirentries] = PLEDGE_RPATH,
#endif
#ifdef SYS_statfs
	[SYS_statfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fstatfs
	[SYS_fstatfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_getfsstat
	[SYS_getfsstat] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_fhstatfs
	[SYS_fhstatfs] = PLEDGE_RPATH, /*  */
#endif
#ifdef SYS_mknodat
	[SYS_mknodat] = PLEDGE_AND | PLEDGE_DEVICE | PLEDGE_CPATH, /*  */
#endif
/* 560: */
#ifdef SYS_kevent
	[SYS_kevent] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_cpuset_getdomain
	[SYS_cpuset_getdomain] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_cpuset_setdomain
	[SYS_cpuset_setdomain] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_getrandom
	[SYS_getrandom] = PLEDGE_NONE, /* */
#endif
#ifdef SYS_getfhat
	[SYS_getfhat] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_fhlink
	[SYS_fhlink] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_fhlinkat
	[SYS_fhlinkat] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_fhreadlink
	[SYS_fhreadlink] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_funlinkat
	[SYS_funlinkat] = PLEDGE_CPATH, /*  */
#endif
#ifdef SYS_copy_file_range
	[SYS_copy_file_range] = PLEDGE_STDIO, /*  */
#endif
/* 570: */
#ifdef SYS___sysctlbyname
	[SYS___sysctlbyname] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_shm_open2
	[SYS_shm_open2] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_shm_rename
	[SYS_shm_rename] = PLEDGE_STDIO, /*  */
#endif
#ifdef SYS_sigfastblock
	[SYS_sigfastblock] = PLEDGE_STDIO, /*  */
#endif
/* 574: */
#ifdef SYS___realpathat
	[SYS___realpathat] = PLEDGE_STDIO, /* 574 */
#endif
};
_Static_assert(575 == SYS_MAXSYSCALL, "new syscalls added, hbsd_pledge.c needs to be updated. TODO would it make sense to remove this static assertion and instead display a helpful message on boot + allow the operator to declare/override the defaults via tunables to prevent situations where people can't boot after upgrading?");
/*
 * Hook used to determine whether a given syscall should be called or not.
 */
int inline
pledge_syscall(struct thread * thread, const int syscall_no)
{
	if (syscall_no < 0 || SYS_MAXSYSCALL <= syscall_no) {
		/* to prevent out-of-bounds access to pledge_permission_map,
		 * default to requiring all privileges in this case,
		 * (TODO and soft-failing would be good)
		 * (prevents breakage when enforcing is off and new
		 * syscalls have been added): */
		return (pledge_check_bitmap(thread,
			PLEDGE_AND | PLEDGE_WILDCARD));
	}

	return (pledge_check_bitmap(thread, pledge_permission_map[syscall_no]));
}

#endif /* ifdef HBSD_PLEDGE */
