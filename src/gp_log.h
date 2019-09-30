/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_LOG_H_
#define _GP_LOG_H_

#include <stdbool.h>
#include <syslog.h>
#include <gssapi/gssapi.h>

extern bool gp_syslog_status;

#define MAX_LOG_LINE 1024
#define GPERROR(...) syslog(LOG_ERR, __VA_ARGS__);
#define GPAUDIT(...) syslog(LOG_INFO, __VA_ARGS__);

void gp_logging_init(void);

void gp_fmt_status(gss_OID mech, uint32_t maj, uint32_t min,
                   char *buf, size_t buf_size);

void gp_log_status(gss_OID mech, uint32_t maj, uint32_t min);

#endif /* _GP_LOG_H_ */
