/* Copyright (C) 2011,2018 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include "gp_debug.h"
#include "gp_log.h"

/* global debug switch */
int gp_debug = 0;

void gp_debug_toggle(int level)
{
    if (level <= gp_debug)
        return;

    if (level >= 3 && !getenv("KRB5_TRACE"))
        setenv("KRB5_TRACE", "/dev/stderr", 1);

    gp_debug = level;
    GPDEBUG("Debug Enabled (level: %d)\n", level);
}

void gp_log_failure(gss_OID mech, uint32_t maj, uint32_t min)
{
    char buf[MAX_LOG_LINE];

    gp_fmt_status(mech, maj, min, buf, MAX_LOG_LINE);

    fprintf(stderr, "Failed with: %s\n", buf);
}

const char *gp_debug_timestamp(void)
{
    static __thread char buffer[24];
    static __thread time_t timestamp = 0;
    struct tm tm_info;
    time_t now;

    time(&now);
    if (now == timestamp) return buffer;

    gmtime_r(&now, &tm_info);
    strftime(buffer, 24, "[%Y/%m/%d %H:%M:%S]: ", &tm_info);
    timestamp = now;
    return buffer;
}

/* thread local connection/client id */
static __thread int cid;

void gp_debug_set_conn_id(int id)
{
    cid = id;
}

static const char*gp_debug_conn_id(void)
{
    static __thread char buffer[18];
    static __thread int last_cid = 0;

    if (cid == 0) {
        buffer[0] = '\0';
        return buffer;
    }

    if (last_cid == cid) return buffer;

    (void)snprintf(buffer, 17, "[CID %d]", cid);
    buffer[17] = '\0';
    last_cid = cid;
    return buffer;
}

void gp_debug_printf(const char *format, ...)
{
    va_list varargs;
    va_start(varargs, format);
    vfprintf(stderr, format, varargs);
    va_end(varargs);
}

void gp_debug_time_printf(const char *format, ...)
{
    va_list varargs;

    fprintf(stderr, "%s%s", gp_debug_conn_id(), gp_debug_timestamp());

    va_start(varargs, format);
    vfprintf(stderr, format, varargs);
    va_end(varargs);
}
