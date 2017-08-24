/* Copyright (C) 2011,2015 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdlib.h>
#include "popt.h"
#include "gp_proxy.h"
#include <signal.h>
#include <string.h>

const int vflags =
    VERTO_EV_FLAG_PERSIST |
    VERTO_EV_FLAG_IO_READ |
    VERTO_EV_FLAG_IO_CLOSE_FD;

char *opt_config_file = NULL;
char *opt_config_dir = NULL;
char *opt_config_socket = NULL;
int opt_daemon = 0;

struct gssproxy_ctx *gpctx;

static struct gp_service *
find_service_by_name(struct gp_config *cfg, const char *name)
{
    int i;
    struct gp_service *ret = NULL;

    for (i = 0; i < cfg->num_svcs; i++) {
        if (strcmp(cfg->svcs[i]->name, name) == 0) {
            ret = cfg->svcs[i];
            break;
        }
    }
    return ret;
}

static verto_ev *setup_socket(char *sock_name, verto_ctx *vctx)
{
    struct gp_sock_ctx *sock_ctx;
    verto_ev *ev;

    sock_ctx = init_unix_socket(gpctx, sock_name);
    if (!sock_ctx) {
        return NULL;
    }

    ev = verto_add_io(vctx, vflags, accept_sock_conn, sock_ctx->fd);
    if (!ev) {
        return NULL;
    }

    verto_set_private(ev, sock_ctx, free_unix_socket);
    return ev;
}

static int init_sockets(verto_ctx *vctx, struct gp_config *old_config)
{
    int i;
    struct gp_sock_ctx *sock_ctx;
    verto_ev *ev;
    struct gp_service *svc;

    /* init main socket */
    if (!old_config) {
        ev = setup_socket(gpctx->config->socket_name, vctx);
        if (!ev) {
            return 1;
        }

        gpctx->sock_ev = ev;
    } else if (strcmp(old_config->socket_name,
                      gpctx->config->socket_name) != 0) {
        ev = setup_socket(gpctx->config->socket_name, vctx);
        if (!ev) {
            return 1;
        }

        gpctx->sock_ev = ev;
        verto_del(gpctx->sock_ev);
    } else {
        /* free_config will erase the socket name; update it accordingly */
        sock_ctx = verto_get_private(gpctx->sock_ev);
        sock_ctx->socket = gpctx->config->socket_name;
    }

    /* propagate any sockets that shouldn't change */
    if (old_config) {
        for (i = 0; i < old_config->num_svcs; i++) {
            if (old_config->svcs[i]->ev) {
                svc = find_service_by_name(gpctx->config,
                                           old_config->svcs[i]->name);
                if (svc &&
                    ((svc->socket == old_config->svcs[i]->socket) ||
                     ((svc->socket != NULL) &&
                      (old_config->svcs[i]->socket != NULL) &&
                      strcmp(svc->socket,
                             old_config->svcs[i]->socket) == 0))) {
                    svc->ev = old_config->svcs[i]->ev;
                    sock_ctx = verto_get_private(svc->ev);
                    sock_ctx->socket = svc->socket;
                } else {
                    verto_del(old_config->svcs[i]->ev);
                }
            }
        }
    }

    /* init all other sockets */
    for (i = 0; i < gpctx->config->num_svcs; i++) {
        svc = gpctx->config->svcs[i];
        if (svc->socket != NULL && svc->ev == NULL) {
            ev = setup_socket(svc->socket, vctx);
            if (!ev) {
                return 1;
            }
            svc->ev = ev;
        }
    }
    return 0;
}

static void hup_handler(verto_ctx *vctx, verto_ev *ev UNUSED)
{
    int ret;
    struct gp_config *new_config, *old_config;

    GPDEBUG("Received SIGHUP; re-reading config.\n");
    new_config = read_config(opt_config_file, opt_config_dir,
                             opt_config_socket, opt_daemon);
    if (!new_config) {
        GPERROR("Error reading new configuration on SIGHUP; keeping old "
                "configuration instead!\n");
        return;
    }
    old_config = gpctx->config;
    gpctx->config = new_config;

    ret = init_sockets(vctx, old_config);
    if (ret != 0) {
        exit(ret);
    }

    /* conditionally reload kernel interface */
    init_proc_nfsd(gpctx->config);

    free_config(&old_config);

    GPDEBUG("New config loaded successfully.\n");
    return;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_interactive = 0;
    int opt_version = 0;
    int opt_debug = 0;
    int opt_debug_level = 0;
    verto_ctx *vctx;
    verto_ev *ev;
    int wait_fd;
    int ret = -1;

    /* initialize debug client id to 0 in the main thread */
    /* we do this early, before any code starts using debug statements */
    gp_debug_set_conn_id(0);

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"daemon", 'D', POPT_ARG_NONE, &opt_daemon, 0, \
         _("Become a daemon (default)"), NULL }, \
        {"interactive", 'i', POPT_ARG_NONE, &opt_interactive, 0, \
         _("Run interactive (not a daemon)"), NULL}, \
        {"config", 'c', POPT_ARG_STRING, &opt_config_file, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"configdir", 'C', POPT_ARG_STRING, &opt_config_dir, 0, \
         _("Specify a non-default config directory"), NULL}, \
        {"socket", 's', POPT_ARG_STRING, &opt_config_socket, 0, \
         _("Specify a custom default socket"), NULL}, \
        {"debug", 'd', POPT_ARG_NONE, &opt_debug, 0, \
         _("Enable debugging"), NULL}, \
        {"debug-level", '\0', POPT_ARG_INT, &opt_debug_level, 0, \
         _("Set debugging level"), NULL}, \
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

            ret = 1;
            goto cleanup;
        }
    }

    if (opt_version) {
        puts(VERSION""DISTRO_VERSION""PRERELEASE_VERSION);
        ret = 0;
        goto cleanup;
    }

    if (opt_debug || opt_debug_level > 0) {
        if (opt_debug_level == 0) opt_debug_level = 1;
        gp_debug_args(opt_debug_level);
    }

    if (opt_daemon && opt_interactive) {
        fprintf(stderr, "Option -i|--interactive is not allowed together with -D|--daemon\n");
        poptPrintUsage(pc, stderr, 0);
        ret = 0;
        goto cleanup;
    }

    if (opt_interactive) {
        opt_daemon = 2;
    }

    gpctx = calloc(1, sizeof(struct gssproxy_ctx));

    gpctx->config = read_config(opt_config_file,
                                opt_config_dir,
                                opt_config_socket,
                                opt_daemon);
    if (!gpctx->config) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    init_server(gpctx->config->daemonize, &wait_fd);

    write_pid();

    vctx = init_event_loop();
    if (!vctx) {
        fprintf(stderr, "Failed to initialize event loop. "
                        "Is there at least one libverto backend installed?\n");
        ret = 1;
        goto cleanup;
    }
    gpctx->vctx = vctx;

    /* Add SIGHUP here so that gpctx is in scope for the handler */
    ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST, hup_handler, SIGHUP);
    if (!ev) {
        fprintf(stderr, "Failed to register SIGHUP handler with verto!\n");
        ret = 1;
        goto cleanup;
    }

    ret = init_sockets(vctx, NULL);
    if (ret != 0) {
        goto cleanup;
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
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = gp_workers_init(gpctx);
    if (ret) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    verto_run(vctx);
    verto_free(vctx);

    gp_workers_free(gpctx->workers);

    fini_server();


    free_config(&gpctx->config);
    free(gpctx);

    ret = 0;

cleanup:
    poptFreeContext(pc);
    free(opt_config_file);
    free(opt_config_dir);
    free(opt_config_socket);

    return ret;
}
