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
#include <stdint.h>
#include "verto.h"

#define _(STRING) gettext(STRING)

/* add element to list head */
#define LIST_ADD(list, elem) do { \
    elem->prev = NULL; \
    elem->next = list; \
    if (list) { \
        list->prev = elem; \
    } \
    list = elem; \
} while (0)

/* remove element from list */
#define LIST_DEL(list, elem) do { \
    if (elem->next) { \
        elem->next->prev = elem->prev; \
    } \
    if (elem->prev) { \
        elem->prev->next = elem->next; \
    } \
    if (list == elem) { \
        list = elem->next; \
    } \
    elem->prev = NULL; \
    elem->next = NULL; \
} while (0)

struct gp_config {
    char *config_file;      /* gssproxy configuration file */
    bool daemonize;         /* let gssproxy daemonize */
    char *socket_name;      /* the socket name to use for */
    int num_workers;        /* number of worker threads */
};

struct gp_workers;

struct gssproxy_ctx {
    struct gp_config *config;
    struct gp_workers *workers;
    verto_ctx *vctx;
};

struct gp_conn;

/* from gp_config.c */
struct gp_config *read_config(char *config_file, int opt_daemonize);

/* from gp_init.c */
void init_server(bool daemonize);
void fini_server(void);
verto_ctx *init_event_loop(void);

/* from gp_socket.c */
int init_unix_socket(const char *file_name);
void accept_sock_conn(verto_ctx *vctx, verto_ev *ev);
void gp_conn_free(struct gp_conn *conn);
void gp_socket_send_data(verto_ctx *vctx, struct gp_conn *conn,
                         uint8_t *buffer, size_t buflen);

/* from gp_workers.c */
int gp_workers_init(struct gssproxy_ctx *gpctx);
void gp_workers_free(struct gp_workers *w);
int gp_query_new(struct gp_workers *w, struct gp_conn *conn,
                 uint8_t *buffer, size_t buflen);

#endif /* _SRV_UTILS_H_ */
