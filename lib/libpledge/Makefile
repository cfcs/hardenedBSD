# $FreeBSD$

.include <bsd.own.mk>

PACKAGE=lib${LIB}
LIB=		pledge

SHLIB_MAJOR=	5

SRCS=		pledge.c
INCS=		pledge.h

MAN=		pledge.3
MLINKS+=	pledge.3 pledge_bitmask_to_string.3
MLINKS+=	pledge.3 pledge_string_to_bitmask.3
MLINKS+=	pledge.3 pledge_string.3

CFLAGS+=-I${.CURDIR}

.include <bsd.lib.mk>
