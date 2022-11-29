/* Copyright (C) 2011,2015 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdlib.h>
#include "popt.h"
#include "gp_proxy.h"
#include <signal.h>
#include <string.h>

char *opt_extract_ccache = NULL;
char *opt_dest_ccache = NULL;

struct gssproxy_ctx *gpctx;

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *opt_config_file = NULL;
    char *opt_config_dir = NULL;
    char *opt_config_socket = NULL;
    int opt_daemon = 0;
    int opt_interactive = 0;
    int opt_version = 0;
    int opt_debug = 0;
    int opt_debug_level = 0;
    int opt_syslog_status = 0;
    int opt_userproxy = 0;
    int opt_idle_timeout = 1000;
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

    /* set tracing function before handling debug level */
    gp_debug_set_krb5_tracing_fn(&gp_krb5_tracing_setup);

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
    if (!gpctx) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    gpctx->config_file = opt_config_file;
    gpctx->config_dir = opt_config_dir;
    gpctx->config_socket = opt_config_socket;
    gpctx->daemonize = opt_daemon;

    if (opt_userproxy) {
        gpctx->userproxymode = true;
        gpctx->config = userproxy_config(gpctx->config_socket,
                                         gpctx->daemonize);
    } else {
        gpctx->config = read_config(gpctx->config_file,
                                    gpctx->config_dir,
                                    gpctx->config_socket,
                                    gpctx->daemonize);
    }
    if (!gpctx->config) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    init_server(gpctx->config->daemonize, opt_userproxy, &wait_fd);

    if (!gpctx->userproxymode) {
        write_pid();
    }

    gpctx->term_timeout = opt_idle_timeout * 1000;

    init_event_loop(gpctx);
    if (!gpctx->vctx) {
        fprintf(stderr, "Failed to initialize event loop. "
                        "Is there at least one libverto backend installed?\n");
        ret = 1;
        goto cleanup;
    }

    if (gpctx->userproxymode) {
        ret = init_userproxy_socket(gpctx);
    } else {
        ret = init_sockets(gpctx, NULL);
    }
    if (ret != 0) {
        goto cleanup;
    }

    /* We need to tell nfsd that GSS-Proxy is available before it starts,
     * as nfsd needs to know GSS-Proxy is in use before the first time it
     * needs to call accept_sec_context. */
    if (!gpctx->userproxymode) {
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

    /* final initialization step */
    ret = init_event_fini(gpctx);
    if (ret) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    verto_run(gpctx->vctx);
    verto_free(gpctx->vctx);

    gp_workers_free(gpctx->workers);

    fini_server();

    ret = 0;

cleanup:
    if (gpctx) {
        free_config(&gpctx->config);
        free(gpctx->config_file);
        free(gpctx->config_dir);
        free(gpctx->config_socket);
        free(gpctx);
    }
    poptFreeContext(pc);
    free(opt_extract_ccache);
    free(opt_dest_ccache);

#ifdef HAVE_VERTO_CLEANUP
    verto_cleanup();
#endif

    return ret;
}
