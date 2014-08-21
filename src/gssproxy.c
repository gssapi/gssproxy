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
#include <stdlib.h>
#include "popt.h"
#include "gp_proxy.h"

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_daemon = 0;
    int opt_interactive = 0;
    int opt_version = 0;
    char *opt_config_file = NULL;
    char *opt_config_socket = NULL;
    int opt_debug = 0;
    verto_ctx *vctx;
    verto_ev *ev;
    int vflags;
    struct gssproxy_ctx *gpctx;
    struct gp_sock_ctx *sock_ctx;
    int wait_fd;
    int ret;
    int i;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"daemon", 'D', POPT_ARG_NONE, &opt_daemon, 0, \
         _("Become a daemon (default)"), NULL }, \
        {"interactive", 'i', POPT_ARG_NONE, &opt_interactive, 0, \
         _("Run interactive (not a daemon)"), NULL}, \
        {"config", 'c', POPT_ARG_STRING, &opt_config_file, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"socket", 's', POPT_ARG_STRING, &opt_config_socket, 0, \
         _("Specify a custom default socket"), NULL}, \
        {"debug", 'd', POPT_ARG_NONE, &opt_debug, 0, \
         _("Enable debugging"), NULL}, \
         {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
          _("Print version number and exit"), NULL }, \
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    if (opt_version) {
        puts(VERSION""DISTRO_VERSION""PRERELEASE_VERSION);
        return 0;
    }

    if (opt_debug) {
        gp_debug_enable();
    }

    if (opt_daemon && opt_interactive) {
        fprintf(stderr, "Option -i|--interactive is not allowed together with -D|--daemon\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (opt_interactive) {
        opt_daemon = 2;
    }

    gpctx = calloc(1, sizeof(struct gssproxy_ctx));

    gpctx->config = read_config(opt_config_file,
                                opt_config_socket,
                                opt_daemon);
    if (!gpctx->config) {
        exit(EXIT_FAILURE);
    }

    init_server(gpctx->config->daemonize, &wait_fd);

    write_pid();

    vctx = init_event_loop();
    if (!vctx) {
        fprintf(stderr, "Failed to initialize event loop. "
                        "Is there at least one libverto backend installed?\n");
        return 1;
    }
    gpctx->vctx = vctx;

    /* init main socket */
    sock_ctx = init_unix_socket(gpctx, gpctx->config->socket_name);
    if (!sock_ctx) {
        return 1;
    }

    vflags = VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ;
    ev = verto_add_io(vctx, vflags, accept_sock_conn, sock_ctx->fd);
    if (!ev) {
        return 1;
    }
    verto_set_private(ev, sock_ctx, NULL);

    /* init secondary sockets */
    for (i = 0; i < gpctx->config->num_svcs; i++) {
        if (gpctx->config->svcs[i]->socket != NULL) {
            sock_ctx = init_unix_socket(gpctx, gpctx->config->svcs[i]->socket);
            if (!sock_ctx) {
                return 1;
            }

            vflags = VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ;
            ev = verto_add_io(vctx, vflags, accept_sock_conn, sock_ctx->fd);
            if (!ev) {
                return 1;
            }
            verto_set_private(ev, sock_ctx, NULL);
        }
    }

    /* We need to tell nfsd that GSS-Proxy is available before it starts,
     * as nfsd needs to know GSS-Proxy is in use before the first time it
     * needs to call accept_sec_context. */
    init_proc_nfsd(gpctx->config);

    /* Now it is safe to tell the init system that we're done starting up,
     * so it can continue with dependencies and start nfsd */
    init_done(wait_fd);

    ret = drop_privs(gpctx->config);
    if (ret) {
        exit(EXIT_FAILURE);
    }

    ret = gp_workers_init(gpctx);
    if (ret) {
        exit(EXIT_FAILURE);
    }

    verto_run(vctx);

    gp_workers_free(gpctx->workers);

    fini_server();

    poptFreeContext(pc);

    free_config(&gpctx->config);

    return 0;
}
