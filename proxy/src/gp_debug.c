/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include "gp_debug.h"
#include "gp_log.h"

/* global debug switch */
int gp_debug;

int gp_debug_args(int level) {
    static int args_level = 0;

    if (level != 0) {
        args_level = level;
    }
    return args_level;
}

void gp_debug_toggle(int level)
{
    static bool krb5_trace_set = false;

    /* Command line and environment options override config file */
    gp_debug = gp_debug_args(0);
    if (gp_debug == 0) {
        gp_debug = level;
    }
    if (level >= 3) {
        if (!getenv("KRB5_TRACE")) {
            setenv("KRB5_TRACE", "/dev/stderr", 1);
            krb5_trace_set = true;
        }
    } else if (krb5_trace_set) {
        unsetenv("KRB5_TRACE");
        krb5_trace_set = false;
    }
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

    fprintf(stderr, "%s", gp_debug_timestamp());

    va_start(varargs, format);
    vfprintf(stderr, format, varargs);
    va_end(varargs);
}
