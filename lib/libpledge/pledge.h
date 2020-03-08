#ifndef _LIB_PLEDGE_H
#define _LIB_PLEDGE_H

/* TODO BSD LICENSE */

// TODO should this file be called libpledge.h instead to avoid colliding with
// <sys/pledge.h> ?

/*
 * Pledge constants and other data types shared between kernel and userland
 * are defined in <sys/pledge.h>
 */

#include <stdint.h>


/*
 * Pledge to use a subset of system call functionality.
 */
int
pledge(const uint64_t _mask);

/*
 * Convert a string policy to a mask.
 * On success, the parsed mask is written to _result_mask.
 * Returns 0 on success, and an error otherwise.
 *
 * Negations using a prefix of '!' is supported, and they take precedence
 * over the whitelisting flags.
 *
 * BNF-syntax, which should go in the `man pledge`
 * SEPARATOR ::= ' ' | '\t' | '\n' | '\r' | '\v' | '\f'
 * NEGATION ::= '!'
 * FLAG ::= "pf" | "rpath" | "wpath" | <... see pledge_string_map in pledge.h>
 * TERM ::= ( NEGATION | "") FLAG
 * TERM-LIST ::= TERM (SEPARATOR TERM-LIST | "" )
 * POLICY ::= (TERM-LIST | "" ) (SEPARATOR | "" ) EOF
 */
int
pledge_string_to_bitmask(const char *_policy, uint64_t *_result_mask);


/*
 * Parse and apply a pledge() policy from a string.
 * Returns 0 on success and an error otherwise.
 * See pledge_string_to_bitmask().
 */
int
pledge_string(const char *_policy);


/*
 * Pretty-prints the string representation of _mask into a newly allocated
 * string and returns a pointer.
 * Returns NULL if not enough memory is available.
 * The caller is responsible for free()'ing the returned buffer.
 * Note that if you're using this from userspace, you might want to use
 * libsysdecode's sysdecode_pledge_flags(), like kdump(1) does, which
 * prints the mask to a FILE *fp instead of malloc()'ing.
 * Also note that at the moment this resides in libc,
 * so good luck calling it from elsewhere. TODO
 */
char *
pledge_bitmask_to_string(const uint64_t _mask);


#endif /* _LIB_PLEDGE_H */
