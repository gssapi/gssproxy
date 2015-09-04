/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include "gp_debug.h"
#include "gp_log.h"

/* global debug switch */
int gp_debug;

void gp_debug_enable(void)
{
    gp_debug = 1;
    GPDEBUG("Debug Enabled\n");
}

void gp_log_failure(gss_OID mech, uint32_t maj, uint32_t min)
{
    char buf[MAX_LOG_LINE];

    gp_fmt_status(mech, maj, min, buf, MAX_LOG_LINE);

    fprintf(stderr, "Failed with: %s\n", buf);
}
