/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1984-2025 John Q. Public
 *
 * Long, boring license goes here, but trimmed for brevity TODO
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>

#include <sys/dirent.h>
#include <sys/extattr.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/pledge.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libxo/xo.h>
#include <pledge.h>

static int verbose = 0;

static const char *const PLEDGECTL_XO_LEARNING_LIST = "learning";
static const char *const CONTAINER_PLEDGECTL = "pledgectl";
static const char *const CONTAINER_PLEDGECTL_VERSION = "1";
/*
 * These are constants for use with xo_open_instance() from libxo.
 * When xo_emit() formats are change, this version number should be bumped.
 */


/* Forward function declarations for utility functions within this file: */
static inline int
print_learning_entry(const pledge_splay_t *const entry,
    const char *const path, const char *const entname);


static void
usage()
{
	xo_warnx("usage: clear:      pledgectl [--libxo] [-v] -c\n"
	    "       list-all:   pledgectl [--libxo] [-v] -L\n"
	    "       list-attr:  pledgectl [--libxo] [-v] -l FILE ...\n"
	    "       set-attr:   pledgectl [--libxo] [-v] -s MASK [FILE ...]\n"
	    "       show usage: pledgectl [--libxo] [-v] -h"
	    "TODO 'local learning mode'/'trace'/'profile' for a given execution\n"
	    "TODO remove extattr from file(s)\n"
	    "TODO -l default to stuff in PATH\n"
		);

	if (verbose) {
		/*
		 * List flags that this version of libpledge was
		 * compiled with:
		 */
		for (unsigned int i = 0; i < sizeof(pledge_string_map)
			/ sizeof(pledge_string_map[0]); i++) {
			xo_emit("{:constant/%18#lx}{P:\t}{:flags}\n",
			    pledge_string_map[i].constant,
			    pledge_string_map[i].name);
		}
	}
}


static int
pledgectl_clear_learning()
{
	xo_errx(2,
	    "TODO Clearing/erasing learning data not currently implemented.\n");
	return (-1);
}

static int
pledgectl_list_extattr(const char *filename)
{
	/*
	 * This is where we read the extattr for argv entry,
	 * stringify it, and print it to stdout.
	 */
	uint64_t pledge_mask = (~0ULL);

	if (!filename) {
		return (2);
	}

	if (sizeof(pledge_mask) == extattr_get_file(filename,
		EXTATTR_NAMESPACE_SYSTEM, "pledge",
		&pledge_mask, sizeof(pledge_mask))) {

		char *mask_str = pledge_bitmask_to_string(pledge_mask);
		if (!mask_str) {
			xo_warnx("Unable to convert pledge flags to string.");
			return (3);
		}

		xo_open_instance("file");
		xo_emit_f(XOEF_RETAIN,
		    "{wc:filename}{wc:pledge-mask/%#lx}{:pledge-str}\n",
		    filename, pledge_mask, mask_str);
		xo_close_instance("file");

		free(mask_str);
		return (0); /* success */
	} else {
		xo_warnx("%s: error: Unable to read 'pledge' extattr "
		    "for file.", filename);
		return (4);
	}
}

static int
pledgectl_set_extattr(const char *filename, const uint64_t new_extattr_mask)
{
	if (sizeof(new_extattr_mask) == extattr_set_file(filename,
		EXTATTR_NAMESPACE_SYSTEM, "pledge",
		&new_extattr_mask, sizeof(new_extattr_mask))) {

		if (verbose > 1) {
			xo_open_instance("file");
			xo_emit_f(XOEF_RETAIN,
			    "{wc:new-mask/%18#lx}{:filename}\n",
			    new_extattr_mask, filename);
			xo_close_instance("file");
		}

		return (0);
	} else {
		xo_warnx("Setting 'pledge' extattr for %s failed.",
		    filename);
		return (5);
	}
}

static int
learning_tree_compare(const pledge_splay_t *const _a,
    const pledge_splay_t *const _b);

static int
learning_tree_compare(
	const struct pledge_splay_t *const a,
	const struct pledge_splay_t *const b)
{
	const ino_t i_diff = a->inode - b->inode;
	return (i_diff || (a->fs_id - b->fs_id));
}

typedef RB_HEAD(learning_tree, pledge_splay_t) learning_tree_t;
static learning_tree_t learning_tree;

RB_PROTOTYPE_STATIC(learning_tree, pledge_splay_t,
    tree_link, learning_tree_compare);
RB_GENERATE_STATIC(learning_tree,
    pledge_splay_t, tree_link, learning_tree_compare);

/*
 * Returns NULL when the entry does not exist in the data retrieved from
 * the kernel.
 */
static const pledge_splay_t *
tree_lookup_learning_entry(const dev_t target_fsid, const ino_t target_inode)
{
	pledge_splay_t stack_el = {
		.inode = target_inode,
		.fs_id = target_fsid,
	};
	return (learning_tree_RB_FIND(&learning_tree, &stack_el));
}

/*
 * Free the elements of the RB tree.
 */
static void
tree_free(void)
{
	pledge_splay_t *np = NULL;
	pledge_splay_t *tmp_next = NULL;
	RB_FOREACH_SAFE(np, learning_tree, &learning_tree, tmp_next) {
		free(learning_tree_RB_REMOVE(&learning_tree, np));
	}
	/* (learning_tree) itself is statically allocated, no free() needed. */
}

/*
 * Build an RB tree from the array of learning data retrieved from the kernel
 * to enable efficient lookups of fsid,inode using tree_lookup_learning_entry().
 * If successful, the tree must subsequently be freed using tree_free().
 */
static int
tree_build(const size_t entry_count,
    const pledge_learning_entry_t *const entries)
{
	size_t cardinality = 0;
	size_t unpopulated = 0;
	size_t merged = 0;
	for (size_t idx = 0; idx < entry_count; idx++) {
		const pledge_learning_entry_t *const entry = entries + idx;
		if (!entry->is_populated) {
			++unpopulated;
			continue;
		}
		pledge_splay_t *new_el = calloc(1, sizeof(pledge_splay_t));
		if (!new_el) {
			xo_warnx("error: not enough memory to "
			    "build tree of learning entries\n");
			return (1);
		}
		new_el->fs_id = entry->fsid;
		new_el->inode = entry->inode;
		pledge_splay_t *el = learning_tree_RB_INSERT(&learning_tree, new_el);
		if (el) {
			/*
			 * Element already existed from other CPU,
			 * we deduplicate and merge into a single entry:
			 */
			++merged;
			free(new_el);
		} else {
			++cardinality;
			el = new_el;
		}
		el->used |= entry->used_flags;
		el->violated |= entry->violated_flags;
		el->possessed |= entry->possessed;
	}
	if (verbose)
		xo_warnx("Merged learning entries from kernel: %zd "
		    "unpopulated: %zd merged: %zd", cardinality, unpopulated, merged);

	return (0);
}

/*
 * Returns 1 if the entry is exempt from printing due to lack of useful
 * information (no used/violated, possessed was "wildcard"),
 * and non-zero on other errors.
 */
static inline int
print_learning_entry(const pledge_splay_t *const entry,
    const char *const path, const char *const entname)
{
	/* Don't print if there's no useful information: */
	if ((PLEDGE_WILDCARD == entry->used  || 0 == entry->used)
	    && 0 == entry->violated
	    && PLEDGE_WILDCARD == entry->possessed
		) return (1);

	char *used_str = pledge_bitmask_to_string(entry->used);
	char *violated_str = pledge_bitmask_to_string(entry->violated);
	char *possessed_str = pledge_bitmask_to_string(entry->possessed);

	if (!used_str || !violated_str || !possessed_str) {
		uint64_t failed = 0;
		if (used_str) free(used_str);
		else failed = entry->used;
		if (violated_str) free(violated_str);
		else failed = entry->violated;
		if (possessed_str) free(possessed_str);
		else failed = entry->possessed;
		xo_warnx("Unable to convert pledge flags %lx to string.",
		    failed);
		return (13);
	}

	// git fetch cfcs hardened/current/pledge && git checkout cfcs/hardened/current/pledge && rm -f /usr/obj/usr/src/amd64.amd64/usr.sbin/pledgectl/pledgectl.full && make && /usr/obj/usr/src/amd64.amd64/usr.sbin/pledgectl/pledgectl.full -v -L ; /usr/obj/usr/src/amd64.amd64/usr.sbin/pledgectl/pledgectl.full -v -l /usr/bin/ncal

	xo_open_instance("entry");

	xo_emit_f(XOEF_RETAIN,
	    "{[:}{:directory}/{:executable}{]:}{P:\t}"
	    "{[:}{Lc:Used}{c:used-flags/%18#lx}{:used}{]:}{P:\t}"
	    "{[:}{C:/%s}{Lc:Violated}{c:violated-flags/%18#lx}{:violated}"
	    "{C:}{]:}{P:\t}"
	    "{[:}{Lc:Possessed}{c:possessed-flags/%18#lx}{:possessed}{]:}\n",
	    path, entname,
	    entry->used, used_str,
	    (entry->violated ? "fg-red" : ""),
	    entry->violated, violated_str,
	    entry->possessed, possessed_str);

	xo_close_instance("entry");

	free(used_str);
	free(violated_str);
	free(possessed_str);

	return (0);
}

static int
pledgectl_dump_all()
{
	/* Learn how many learning data entries the kernel has for us: */
	size_t requested_bytes = 0 ;
	int err = sysctlbyname("security.pledge.learning_data",
	    NULL, &requested_bytes, NULL, 0);
	if (err) {
		xo_warnx("Unable to obtain count of live learning entries.");
		return (7);
	}

	/*
	 * Since the kernel estimate is a conservative estimate due to lack of
	 * synchronization between the CPU fetching the counter value and the
	 * other CPUs, we ask for a few extra entries. This lets us pick up data
	 * for executables that have not been scheduled on the CPU handling our
	 * sysctl, and which hasn't synchronized its counter recently.
	 * Asking for too many entries is not a problem, it will just render us
	 * with some entry learning data slots (and a bit more memory used):
	 */
	requested_bytes += 256 * sizeof(pledge_learning_entry_t);

	const size_t requested_entry_count = requested_bytes
	    / sizeof(pledge_learning_entry_t);

	if (verbose && requested_entry_count) {
		xo_warnx("Kernel reports having %zd learning entries.",
		    requested_entry_count - 256);
	}

	/* Allocate memory for the array of entries to receive from kernel: */
	pledge_learning_entry_t *entries = calloc(requested_entry_count,
	    sizeof(pledge_learning_entry_t));

	if (!entries) {
		xo_warnx("Unable to allocate %zd bytes for %zd entries.",
		    requested_bytes, requested_entry_count);
		return (8);
	}

	size_t actual_bytes = requested_bytes;
	err = sysctlbyname("security.pledge.learning_data",
	    entries, &actual_bytes, NULL, 0);
	if (err) {
		free(entries);
		xo_warn("Unable to obtain learning entries"
		    " from kernel (%d).", err);
		return (9);
	}

	assert(actual_bytes <= requested_bytes);
	assert(0 == actual_bytes % sizeof(pledge_learning_entry_t));

	size_t actual_count = actual_bytes / sizeof(pledge_learning_entry_t);

	assert (actual_count <= requested_entry_count);

	if (!actual_count) {
		// if (verbose)
		xo_warnx("No learning data recorded."
		    " Check that sysctl security.pledge.learning=1");
		free(entries);
		return (0);
	}

	RB_INIT(&learning_tree);
	err = tree_build(actual_count, entries);
	free(entries);
	if (err) {
		xo_warnx("error: Failed to build tree.");
		return (err);
	}

	struct statfs *statfs_array = NULL;
	size_t filesystem_count = getmntinfo(&statfs_array, MNT_WAIT);

	if (!filesystem_count) {
		xo_warn("Unable to obtain information about "
		    "mounted filesystems.");
		return (15);
	}

	/*
	 * We loop over each dir in $PATH, look up inode+fsid for each in our
	 * tree of learning data. When we have data about an executable, we
	 * examine it and print it if it contains any useful information.
	 */
	char *paths = strdup(getenv("PATH"));
	if (!paths) {
		xo_warnx("no $PATH given.");
		/* statsfs_array is static, can't free */
		return (17);
	}

	xo_open_list(PLEDGECTL_XO_LEARNING_LIST);

	unsigned int ignored = 0;

	char *dir_path = NULL;
	while (NULL != (dir_path = strsep(&paths, ":"))) {
		DIR *fd_dir = opendir(dir_path);
		if (!fd_dir) {
			continue;
		}
		/* Loop over each regular file in dir_path: */
		const struct dirent *dirent = NULL;
		while (NULL != (dirent = readdir(fd_dir))) {
			struct stat file_stat = {0};
			if (DT_REG != dirent->d_type) {
				continue; /* Next entry in fd_dir */
			}
			if (fstatat(dirfd(fd_dir), dirent->d_name,
				&file_stat, 0)) {
				xo_warn("couldn't stat %s/%s",
				    dir_path, dirent->d_name);
				continue;
			}
			if (!S_ISREG(file_stat.st_mode)){
				continue; /* Next entry in fd_dir */
			}
			const pledge_splay_t *const entry =
			    tree_lookup_learning_entry(file_stat.st_dev,
				file_stat.st_ino);
			if (NULL == entry) {
				if (verbose >= 2) {
					xo_warnx("%s/%s: no learning data",
					    dir_path, dirent->d_name);
				}
			}
			else switch (print_learning_entry(entry, dir_path,
				dirent->d_name)) {
				case 0:
					break;
				case 1:
					++ignored;
					break;
				default:
					xo_warnx("error printing for %s/%s",
					    dir_path, dirent->d_name);
			}
		}
		if (closedir(fd_dir)) {
			xo_warn("%s: error: ", dir_path);
		}
	}

	free(paths);
	tree_free();

	xo_close_list(PLEDGECTL_XO_LEARNING_LIST);
	if (ignored && verbose) {
		xo_emit("{Lwc:Ignored entries}{:ignored-entries/%u}\n",
		    ignored);
	}

	return (0);
}

int main(int argc, char *argv[])
{
	int err = 0;
	/*
	 * Drop unneeded privileges:
	 */
	err = pledge(PLEDGE_STDIO | PLEDGE_RPATH | PLEDGE_FATTR
	    | PLEDGE_DEVICE);

	xo_set_flags(NULL, XOF_WARN | XOF_COLUMNS);
	argc = xo_parse_args(argc, argv);
	xo_set_version(CONTAINER_PLEDGECTL_VERSION);
	xo_open_container(CONTAINER_PLEDGECTL);

	if (err)
		xo_errx(1, "pledgectl: Setting pledge mask failed. "
		    "Is kernel compiled with config 'option HBSD_PLEDGE' ?\n");;

	if (argc < 1) {
		xo_warnx("error: not enough arguments");
	}

	/*
	 * Parse command-line options:
	 */

	enum { UNSET, CLEAR_LEARNING, DUMP_ALL, LIST_EXTATTR,
	       SET_EXTATTR } action = UNSET;

	int ch = (-1); /* getopt variable */

	/* pledge privs to assign to extattr: */
	uint64_t new_extattr_mask = PLEDGE_NONE;

	while ((ch = getopt(argc, argv, "chLls:v")) != -1) {

		/*
		 * Only permit ONE action:
		 */
		switch (ch) {
		case 'c':
		case 'L':
		case 'l':
		case 's':
			if (UNSET != action) {
				xo_warnx("conflicting option -%c", ch);
				action = UNSET;
				argc = 0;
			}
			break;
		case '?':
			xo_warnx("error: unrecognized option -%c", optopt);
			break;
		}

		switch (ch) {
		case 'c':
			action = CLEAR_LEARNING; break;
		case 'L':
			action = DUMP_ALL; break;
		case 'l':
			action = LIST_EXTATTR; break;
		case 's':
			if (PLEDGE_NONE != new_extattr_mask) {
				xo_warnx("error: -s given more than once");
				action = UNSET;
				break;
			}

			intptr_t res =
			    pledge_string_to_bitmask(optarg, &new_extattr_mask);
			if ( res < 0 ||
			    (res > 0 && (unsigned long)res >= strlen(optarg))) {
				xo_errx(14,
				    "error: Unable to parse -s argument '%s'.",
					optarg);
			} else if (res > 0) {
				/* Underline offending char: */
				// TODO PRIuPTR ?
				xo_errx(15,
				    "error: Unable to parse -s argument '"
				    "%.*s\033[4m%c\033[0m%s'"
				    " error at offset %d,".
				    (int)res, optarg,
				    *(optarg + res), optarg + res + 1,
				    (int)res);
			}

			if (verbose) {
				char *str = pledge_bitmask_to_string(
					new_extattr_mask);
				if (str) {
					xo_emit("{Lwc:New pledge mask}"
					    "{wc:new-mask/%18#lx}"
					    "{:new-strmask}\n",
					    new_extattr_mask, str);
					free(str);
				}
			}
			action = SET_EXTATTR;
			break;
		case 'v':
			verbose++;
			break;
		default:
			/* -h and unrecognized flags will end here: */
			action = UNSET;
			argc = 0;
		}
	}
	argc -= optind;
	argv += optind;

	/* pledge privs required for requested action */
	uint64_t action_mask = PLEDGE_STDIO;
	switch (action) {
	case LIST_EXTATTR:
		action_mask |= PLEDGE_RPATH; break;
	case DUMP_ALL:
		action_mask |= PLEDGE_RPATH | PLEDGE_DEVICE; break;
	case SET_EXTATTR:
		action_mask |= PLEDGE_FATTR; break;
	case CLEAR_LEARNING:
		action_mask |= PLEDGE_DEVICE; break;
	default: break;
	}

	if (pledge(action_mask)) {
		xo_warnx("error: Unable to drop privileges for the "
		    "requested action.");
		goto finish;
	}

	/*
	 * Perform requested actions:
	 */
	switch (action) {
	case CLEAR_LEARNING:	/* Erase learning data in kernel with sysctl */
		err = pledgectl_clear_learning();
		break;

	case DUMP_ALL:		/* Dump from kernel with sysctl */
		err = pledgectl_dump_all();
		break;

	case LIST_EXTATTR:	/* Retrieve extattr pledge mask */
		xo_open_list("list-extattr");
		while (argc) {
			err |= pledgectl_list_extattr( argv[--argc] );
		}
		xo_close_list("list-extattr");
		break;

	case SET_EXTATTR:	/* Set extattr pledge mask for executable */
		xo_open_list("set-extattr");
		while (argc) {
			err |= pledgectl_set_extattr( argv[--argc],
			    new_extattr_mask );
		}
		xo_open_list("set-extattr");
		break;

	case UNSET:
	default:
		usage();
	}

finish:
	xo_close_container(CONTAINER_PLEDGECTL);
	xo_flush(); // TODO is flush needed here??
	xo_finish();

	return (err);
}
