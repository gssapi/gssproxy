/* Copyright (C) 2011,2018 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_DEBUG_H_
#define _GP_DEBUG_H_

#include <gssapi/gssapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#define GP_INFO_DEBUG_LVL 1

extern int gp_debug;

void gp_debug_toggle(int);
void gp_debug_printf(const char *format, ...);
void gp_debug_time_printf(const char *format, ...);
void gp_debug_set_conn_id(int id);
void gp_debug_set_krb5_tracing_fn(void (*fn)(int));

#define GPDEBUG(...) do { \
    if (gp_debug) { \
        gp_debug_time_printf(__VA_ARGS__); \
    } \
} while(0)

#define GPDEBUGN(lvl, ...) do { \
    if (lvl <= gp_debug) { \
        gp_debug_time_printf(__VA_ARGS__); \
    } \
} while(0)

void gp_log_failure(gss_OID mech, uint32_t maj, uint32_t min);

#endif /* _GP_DEBUG_H_ */
