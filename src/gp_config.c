/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include "gp_utils.h"
#include "iniparser.h"

#define GP_SOCKET_NAME "gssproxy.socket"

int load_config(struct gp_config *cfg)
{
    dictionary *d;
    char *tmpstr;
    int ret;

    d = iniparser_load(cfg->config_file);
    if (!d) {
        return ENOENT;
    }

    tmpstr = iniparser_getstring(d, "gssproxy:socket", NULL);
    if (tmpstr) {
        cfg->socket_name = strdup(tmpstr);
        if (!cfg->socket_name) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = asprintf(&cfg->socket_name, "%s/%s",
                        PIPE_PATH, GP_SOCKET_NAME);
        if (ret == -1) {
            ret = ENOMEM;
            goto done;
        }
    }

    cfg->num_workers = iniparser_getint(d, "gssproxy:worker threads", 0);

done:
    iniparser_freedict(d);
    return ret;
}

struct gp_config *read_config(char *config_file, int opt_daemonize)
{
    struct gp_config *cfg;
    int ret;

    cfg = calloc(1, sizeof(struct gp_config));
    if (!cfg) {
        return NULL;
    }

    if (config_file) {
        cfg->config_file = strdup(config_file);
        if (!cfg->config_file) {
            free(cfg);
            return NULL;
        }
    } else {
        ret = asprintf(&cfg->config_file, "%s/gssproxy.conf", PUBCONF_PATH);
        if (ret == -1) {
            free(cfg);
            return NULL;
        }
    }

    switch (opt_daemonize) {
    case 0:
        /* daemonize by default */
    case 1:
        cfg->daemonize = true;
        break;
    case 2:
        cfg->daemonize = false;
        break;
    }

    ret = load_config(cfg);
    if (ret) {
        syslog(LOG_INFO, "Config file not found! Proceeding with defaults.");
    }

    return cfg;
}

