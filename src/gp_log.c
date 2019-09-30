/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include "gp_log.h"
#include <stdio.h>
#include <stdarg.h>

/* global logging switch */
bool gp_syslog_status = false;

void gp_logging_init(void)
{
    openlog("gssproxy",
            LOG_CONS|LOG_NDELAY|LOG_NOWAIT|LOG_PERROR|LOG_PID,
            LOG_AUTHPRIV);
}
static size_t gp_append(char *buf, size_t max, const char *fmt, ...)
{
    va_list ap;
    size_t res;

    if (max <= 0) return 0;

    va_start(ap, fmt);
    res = vsnprintf(buf, max, fmt, ap);
    va_end(ap);

    return res;
}

void gp_fmt_status(gss_OID mech, uint32_t maj, uint32_t min,
                   char *buf, size_t buf_size)
{
    uint32_t msgctx;
    uint32_t discard;
    gss_buffer_desc tmp;
    size_t used = 0;

    if (mech != GSS_C_NO_OID) {
        gss_oid_to_str(&discard, mech, &tmp);
        used += gp_append(buf + used, buf_size - used,
                          "(OID: %s) ", (char *)tmp.value);
        gss_release_buffer(&discard, &tmp);
    }

    msgctx = 0;
    gss_display_status(&discard, maj, GSS_C_GSS_CODE, mech, &msgctx, &tmp);
    used += gp_append(buf + used, buf_size - used, "%s, ", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);

    msgctx = 0;
    gss_display_status(&discard, min, GSS_C_MECH_CODE, mech, &msgctx, &tmp);
    used += gp_append(buf + used, buf_size - used, "%s", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);
}

void gp_log_status(gss_OID mech, uint32_t maj, uint32_t min)
{
    char buf[MAX_LOG_LINE];

    if (!gp_syslog_status)
        return;

    gp_fmt_status(mech, maj, min, buf, MAX_LOG_LINE);
    syslog(LOG_DEBUG, "%s\n", buf);
}
