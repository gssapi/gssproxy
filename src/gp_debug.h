/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_DEBUG_H_
#define _GP_DEBUG_H_

#include <gssapi/gssapi.h>
#include <stdio.h>

extern int gp_debug;

void gp_debug_enable(void);

#define GPDEBUG(...) do { \
    if (gp_debug) { \
        fprintf(stderr, __VA_ARGS__); \
    } \
} while(0)

void gp_log_failure(gss_OID mech, uint32_t maj, uint32_t min);

#endif /* _GP_DEBUG_H_ */
