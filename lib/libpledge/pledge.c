#include <sys/pledge.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "pledge.h"

/* Cached security.pledge.flags MIB */
static int security_pledge_flags[3] = {0};

__attribute__ ((constructor)) static void
libpledge_initialize(void)
{
	size_t len = 3;
	_Static_assert((sizeof(security_pledge_flags)/sizeof(int) == 3),
	    "pledge MIB != 3");
	if (sysctlnametomib("security.pledge.flags",
		(int *) &security_pledge_flags, &len))
	{
		//perror("pledgectl");
		fprintf(stderr,
		    "libpledge: failed to resolve pledge sysctl MIB\n");
		exit(1);
	}
}

/*
 * Wrapper for the security.pledge.flags sysctl.
 * On error, errno is set to indicate the error.
 */
int
pledge(const uint64_t mask)
{
	return (sysctl(security_pledge_flags, 3, NULL, NULL,
		&mask, sizeof(mask)));
}

/*
 * State machine for pledge_str() below
 */
enum pledge_str_state { LOOK_FOR_WHITESPACE, TERM, NEGATED_TERM };

/*
 * TODO
 * Convert a human-readable string to a pledge bitmask.
 * &output_mask is only set if the parsing was successful.
 * On success returns 0, on error returns EINVAL.
 * errno is always set to 0.
 */
int
pledge_string_to_bitmask(const char *const policy, uint64_t *output_mask)
{
	uint64_t whitelist = PLEDGE_NONE;
	uint64_t blacklist = PLEDGE_NONE;
	enum pledge_str_state state = TERM;

	if (!policy || !output_mask)
		return (EINVAL);

	{ /* Raw integer mask */
		char *invalid = NULL;
		errno = 0;
		uint64_t raw = strtoull(policy, &invalid, 0);
		if ( !errno && '\0' == *invalid) {
			*output_mask = raw;
			return (0);
		}
	}

	const char *const stop = policy + strlen(policy);
	for (const char *ptr = policy; ptr < stop; ptr++) {

		switch (state) {
		case NEGATED_TERM:
			if (isspace(*ptr)) continue;
			break;
		case TERM:
			if ('!' == *ptr) {
				state = NEGATED_TERM;
				continue;
			} else if (isspace(*ptr)) continue;
			break;
		case LOOK_FOR_WHITESPACE:
			if (isspace(ptr[0])) {
				state = TERM;
				continue;
			}
			/* Expecting whitespace, got something else: */
			/* TODO if we returned the index of the invalid char
			 * this function would be a lot more useful to people
			 * having issues with the syntax. */
			return (EINVAL);
		}

		for (size_t idx = 0;
		     idx < sizeof(pledge_string_map)
			 / sizeof(pledge_string_map[0]); idx++) {

			size_t namelen = strlen(pledge_string_map[idx].name);
			// TODO locale-dependent, use C locale instead:
			/*
			 * Test for common prefix and termination with
			 * either space or \0 :
			 */
			if (0 != strncasecmp(ptr,
				pledge_string_map[idx].name, namelen)
			    || (*(ptr + namelen) | ' ') != ' ')
				continue;

			if (NEGATED_TERM == state) {
				blacklist |= pledge_string_map[idx].constant;
			} else {
				assert(TERM == state);
				whitelist |= pledge_string_map[idx].constant;
			}
			/* -1 because ptr++ at end of loop: */
			ptr += namelen - 1;
			state = LOOK_FOR_WHITESPACE;
			break;
		}

		/* If we are still looking for a term, we didn't find
		 * a match in pledge_string_map: */
		if (LOOK_FOR_WHITESPACE != state)
			return (EINVAL);
	}

	/*
	 * Let blacklist take precedence over whitelist by applying the
	 * intersection of the whitelist and the inverse of the blacklist:
	 */
	*output_mask = (whitelist & ~blacklist);
	return (0);
}

/*
 * Parse and apply a pledge() policy from a string.
 * Returns 0 on success and an error otherwise.
 * See sys/pledge.h
 */
int pledge_string(const char *policy)
{
	uint64_t mask = PLEDGE_NONE;
	int err = pledge_string_to_bitmask(policy, &mask);
	if (err) {
		return (err);
	}
	return (pledge(mask));
}

/*
 * Pretty-prints the string representation of _mask into a newly allocated
 * string and returns a pointer.
 * Returns NULL if not enough memory is available.
 * The caller is responsible for free()'ing the returned buffer.
 */
char *
pledge_bitmask_to_string(const uint64_t mask)
{
	size_t length = 1; /* At least the trailing \0 */
	char *ret = NULL;
	char *off = NULL;

	/* Compute size required for the returned buffer: */

	uint64_t space_mask = mask;
	for (size_t i = 0;
	     i < sizeof(pledge_string_map)
		 / sizeof(pledge_string_map[0]); i++) {
		const uint64_t target = pledge_string_map[i].constant;
		if ((target & space_mask) == target) {
			/* Reserve space for ' ' (space) + name: */
			length += 1 + strlen(pledge_string_map[i].name);
			/* Unset all bits covered by this mask to prevent
			 * double matches: */
			space_mask &= ~target;
			/* Do not emit "none" if we have other flags: */
			if (!space_mask) break;
		}
	}

	if (length > 1) --length; /* Adjust space prefix for first element */

	off = ret = calloc(1, length);
	if (NULL == ret) {
		return (NULL);
	}

	/* Set string: */

	uint64_t string_mask = mask;
	for (size_t i = 0;
	     i < sizeof(pledge_string_map)
		 / sizeof(pledge_string_map[0]); i++) {
		const uint64_t target = pledge_string_map[i].constant;
		if ((target & string_mask) == target) {
			off = stpcpy(off, pledge_string_map[i].name);
			/* Unset all bits covered by this mask to prevent
			 * double matches: */
			string_mask &= ~target;
			/* If all flags decoded and at least one outputted: */
			if (!string_mask) break;
			/* We have more flags left, append space separator: */
			*off++ = ' ';
		}
	}

	return (ret);
}
