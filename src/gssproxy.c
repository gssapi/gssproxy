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
char *opt_extract_ccache = NULL;
char *opt_dest_ccache = NULL;
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

static verto_ev *setup_socket(char *sock_name, verto_ctx *vctx,
                              bool with_activation)
{
    struct gp_sock_ctx *sock_ctx = NULL;
    verto_ev *ev;

#ifdef HAVE_SYSTEMD_DAEMON
    if (with_activation) {
        int ret;
        /* try to se if available, fallback otherwise */
        ret = init_activation_socket(gpctx, &sock_ctx);
        if (ret) {
            return NULL;
        }
    }
#endif
    if (!sock_ctx) {
        /* no activation, try regular socket creation */
        sock_ctx = init_unix_socket(gpctx, sock_name);
    }
    if (!sock_ctx) {
        return NULL;
    }

    ev = verto_add_io(vctx, vflags, accept_sock_conn, sock_ctx->fd);
    if (!ev) {
        free(sock_ctx);
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
        ev = setup_socket(gpctx->config->socket_name, vctx, false);
        if (!ev) {
            return 1;
        }

        gpctx->sock_ev = ev;
    } else if (strcmp(old_config->socket_name,
                      gpctx->config->socket_name) != 0) {
        ev = setup_socket(gpctx->config->socket_name, vctx, false);
        if (!ev) {
            return 1;
        }

        verto_del(gpctx->sock_ev);
        gpctx->sock_ev = ev;
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
            ev = setup_socket(svc->socket, vctx, false);
            if (!ev) {
                return 1;
            }
            svc->ev = ev;
        }
    }
    return 0;
}

static int init_userproxy_socket(verto_ctx *vctx)
{
    verto_ev *ev;

    /* init main socket */
    ev = setup_socket(gpctx->config->socket_name, vctx, true);
    if (!ev) {
        return 1;
    }

    gpctx->sock_ev = ev;
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

void break_loop(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    if (ev == gpctx->term_ev) {
        gpctx->term_ev = NULL;
    }
    GPDEBUG("Exiting!\n");
    gpctx->terminate = true;
}

static void idle_handler(verto_ctx *vctx)
{
    /* we've been called, this means some event just fired,
     * restart the timeout handler */

    if (gpctx->term_timeout == 0) {
        /* self termination is disabled */
        return;
    }

    verto_del(gpctx->term_ev);

    /* Add self-termination timeout */
    gpctx->term_ev = verto_add_timeout(vctx, VERTO_EV_FLAG_NONE,
                                       break_loop, gpctx->term_timeout);
    if (!gpctx->term_ev) {
        GPDEBUG("Failed to register timeout event!\n");
    }
}

static void do_loop(verto_ctx *vctx)
{
    while(gpctx->terminate == false) {
        verto_run_once(vctx);
        idle_handler(vctx);
    }
}

static void init_event(verto_ctx *vctx UNUSED, verto_ev *ev UNUSED)
{
    GPDEBUG("Initialization complete.\n");
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_interactive = 0;
    int opt_version = 0;
    int opt_debug = 0;
    int opt_debug_level = 0;
    int opt_syslog_status = 0;
    int opt_userproxy = 0;
    int opt_idle_timeout = 1000;
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
        {"userproxy", 'u', POPT_ARG_NONE, &opt_userproxy, 0, \
         _("Simplified user session proxy"), NULL}, \
        {"debug", 'd', POPT_ARG_NONE, &opt_debug, 0, \
         _("Enable debugging"), NULL}, \
        {"debug-level", '\0', POPT_ARG_INT, &opt_debug_level, 0, \
         _("Set debugging level"), NULL}, \
        {"syslog-status", '\0', POPT_ARG_NONE, &opt_syslog_status, 0, \
         _("Enable GSSAPI status logging to syslog"), NULL}, \
        {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
         _("Print version number and exit"), NULL }, \
        {"idle-timeout", '\0', POPT_ARG_INT, &opt_idle_timeout, 0, \
        _("Set idle timeout for user mode (default: 1000s)"), NULL },
        {"extract-ccache", '\0', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, \
         &opt_extract_ccache, 0, \
        _("Extract a gssproxy encrypted ccache"), NULL },
        {"into-ccache", '\0', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN, \
        &opt_dest_ccache, 0, \
        _("Destination ccache for extracted ccache"), NULL },
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
        gp_debug_toggle(opt_debug_level);
    }

    if (opt_extract_ccache) {
        ret = extract_ccache(opt_extract_ccache, opt_dest_ccache);
        goto cleanup;
    }

    if (opt_syslog_status)
        gp_syslog_status = true;

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

    if (opt_userproxy) {
        gpctx->config = userproxy_config(opt_config_socket, opt_daemon);
    } else {
        gpctx->config = read_config(opt_config_file,
                                    opt_config_dir,
                                    opt_config_socket,
                                    opt_daemon);
    }
    if (!gpctx->config) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    init_server(gpctx->config->daemonize, opt_userproxy, &wait_fd);

    if (!opt_userproxy) {
        write_pid();
    }

    gpctx->term_timeout = opt_idle_timeout * 1000;

    vctx = init_event_loop();
    if (!vctx) {
        fprintf(stderr, "Failed to initialize event loop. "
                        "Is there at least one libverto backend installed?\n");
        ret = 1;
        goto cleanup;
    }
    gpctx->vctx = vctx;

    if (!opt_userproxy) {
        /* Add SIGHUP here so that gpctx is in scope for the handler */
        ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST,
                              hup_handler, SIGHUP);
        if (!ev) {
            fprintf(stderr, "Failed to register SIGHUP handler with verto!\n");
            ret = 1;
            goto cleanup;
        }
    }

    if (opt_userproxy) {
        ret = init_userproxy_socket(vctx);
    } else {
        ret = init_sockets(vctx, NULL);
    }
    if (ret != 0) {
        goto cleanup;
    }

    /* We need to tell nfsd that GSS-Proxy is available before it starts,
     * as nfsd needs to know GSS-Proxy is in use before the first time it
     * needs to call accept_sec_context. */
    if (!opt_userproxy) {
        init_proc_nfsd(gpctx->config);
    }

    /* Now it is safe to tell the init system that we're done starting up,
     * so it can continue with dependencies and start nfsd */
    init_done(wait_fd);

    /* if config option "run_as_user" is missing, then it's no need to
     * drop privileges */
    if (gpctx->config->proxy_user) {
        ret = drop_privs(gpctx->config);
        if (ret) {
            ret = EXIT_FAILURE;
            goto cleanup;
        }
    }

    ret = gp_workers_init(gpctx);
    if (ret) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* Schedule an event to run as soon as the event loop is started
     * This is useful in debug to know that all initialization is done.
     * Might be used in future to schdule startup one offs that do not
     * need to be done synchronously */
    ev = verto_add_timeout(vctx, VERTO_EV_FLAG_NONE, init_event, 1);
    if (!ev) {
        fprintf(stderr, "Failed to register init_event with verto!\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    do_loop(vctx);
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
    free(opt_extract_ccache);
    free(opt_dest_ccache);

#ifdef HAVE_VERTO_CLEANUP
    verto_cleanup();
#endif

    return ret;
}
