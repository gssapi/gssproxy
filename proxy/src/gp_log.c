/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Simo Sorce <simo.sorce@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "config.h"
#include "gp_log.h"
#include <stdio.h>
#include <stdarg.h>

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

    gp_fmt_status(mech, maj, min, buf, MAX_LOG_LINE);

    GPERROR("%s\n", buf);
}
