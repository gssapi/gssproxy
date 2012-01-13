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

#ifndef _SRV_UTILS_H_
#define _SRV_UTILS_H_

#include <libintl.h>
#include <stdbool.h>
#include "verto.h"

#define _(STRING) gettext(STRING)

struct gp_config {
    char *config_file;
    bool daemonize;
    char *socket_name;
};

/* from gp_config.c */
struct gp_config *read_config(char *config_file, int opt_daemonize);

/* from gp_init.c */
void init_server(bool daemonize);
void fini_server(void);
verto_ctx *init_event_loop(void);

/* from gp_socket.c */
int init_unix_socket(const char *file_name);
void accept_sock_conn(verto_ctx *vctx, verto_ev *ev);

#endif /* _SRV_UTILS_H_ */
