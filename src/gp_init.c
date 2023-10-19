/* Copyright (C) 2011,2015 the GSS-PROXY contributors, see COPYING for license */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <locale.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#ifdef HAVE_CAP

#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#endif

#include "gp_proxy.h"

void init_server(bool daemonize, int userproxy, int *wait_fd)
{
    pid_t pid, sid;
    int ret;

    *wait_fd = -1;

    if (daemonize) {
        int pipefd[2];
        char buf[1];

        /* create parent-child pipe */
        ret = pipe(pipefd);
        if (ret == -1) {
            exit(EXIT_FAILURE);
        }

        pid = fork();
        if (pid == -1) {
            /* fork error ? abort */
            exit(EXIT_FAILURE);
        }
        if (pid != 0) {
            /* wait for child to signal it is ready */
            close(pipefd[1]);
            ret = gp_safe_read(pipefd[0], buf, 1);
            if (ret == 1) {
                /* child signaled all ok */
                exit(EXIT_SUCCESS);
            } else {
                /* lost child, something went wrong */
                exit(EXIT_FAILURE);
            }
        }

        /* child */
        close(pipefd[0]);
        *wait_fd = pipefd[1];

        sid = setsid();
        if (sid == -1) {
            /* setsid error ? abort */
            exit(EXIT_FAILURE);
        }
    }

    /* we set none of the following in userproxy mode, as the user proxy
     * is intended to work as a user process in a regular user session
     * proxing for other user processes like flatpak based applications
     * that run effectively in a separate container */
    if (userproxy) return;

    ret = chdir("/");
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }

    /* Set strict umask by default */
    umask(0177);

    /* Set up neutral locale */
    setlocale(LC_ALL, "");

    /* Set env var to avoid looping to ourselves in GSSAPI */
    setenv("GSS_USE_PROXY", "NO", 1);

    gp_logging_init();
}

void init_done(int wait_fd)
{
    char buf = 0;
    int ret;

    if (wait_fd != -1) {
        ret = gp_safe_write(wait_fd, &buf, 1);
        if (ret != 1) {
            exit(EXIT_FAILURE);
        }
        close(wait_fd);
    }
}

void fini_server(void)
{
    gp_krb5_fini_tracing();
    closelog();
}

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

const int vflags =
    VERTO_EV_FLAG_PERSIST |
    VERTO_EV_FLAG_IO_READ |
    VERTO_EV_FLAG_IO_CLOSE_FD;

static verto_ev *setup_socket(struct gssproxy_ctx *gpctx, char *sock_name,
                              bool with_activation)
{
    struct gp_sock_ctx *sock_ctx = NULL;
    verto_ev *ev;

#ifdef HAVE_SYSTEMD_DAEMON
    if (with_activation) {
        int ret;
        /* try to se if available, fallback otherwise */
        ret = init_activation_socket(gpctx, sock_name, &sock_ctx);
        if (ret) {
            return NULL;
        }
    }
#endif
    if (!sock_ctx) {
        /* disable self termination as we are not socket activated */
        gpctx->term_timeout = 0;

        /* no activation, try regular socket creation */
        sock_ctx = init_unix_socket(gpctx, sock_name);
    }
    if (!sock_ctx) {
        return NULL;
    }

    ev = verto_add_io(gpctx->vctx, vflags, accept_sock_conn, sock_ctx->fd);
    if (!ev) {
        free(sock_ctx);
        return NULL;
    }

    verto_set_private(ev, sock_ctx, free_unix_socket);
    return ev;
}

int init_sockets(struct gssproxy_ctx *gpctx, struct gp_config *old_config)
{
    int i;
    struct gp_sock_ctx *sock_ctx;
    verto_ev *ev;
    struct gp_service *svc;

    /* init main socket */
    if (!old_config) {
        ev = setup_socket(gpctx, gpctx->config->socket_name, false);
        if (!ev) {
            return 1;
        }

        gpctx->sock_ev = ev;
    } else if (strcmp(old_config->socket_name,
                      gpctx->config->socket_name) != 0) {
        ev = setup_socket(gpctx, gpctx->config->socket_name, false);
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
                    old_config->svcs[i]->ev = NULL;
                }
            }
        }
    }

    /* init all other sockets */
    for (i = 0; i < gpctx->config->num_svcs; i++) {
        svc = gpctx->config->svcs[i];
        if (svc->socket != NULL && svc->ev == NULL) {
            ev = setup_socket(gpctx, svc->socket, false);
            if (!ev) {
                return 1;
            }
            svc->ev = ev;
        }
    }
    return 0;
}

int init_userproxy_socket(struct gssproxy_ctx *gpctx)
{
    verto_ev *ev;

    /* init main socket */
    ev = setup_socket(gpctx, gpctx->config->socket_name, true);
    if (!ev) {
        return 1;
    }

    gpctx->sock_ev = ev;
    return 0;
}

static void hup_handler(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    int ret;
    struct gssproxy_ctx *gpctx;
    struct gp_config *new_config, *old_config;

    gpctx = verto_get_private(ev);

    sd_notifyf(0, "RELOADING=1\n"
               "MONOTONIC_USEC=%" PRIu64 "\n"
               "STATUS=Reloading configuration\n",
               time_now_usec());

    GPDEBUG("Received SIGHUP; re-reading config.\n");
    new_config = read_config(gpctx->config_file, gpctx->config_dir,
                             gpctx->config_socket, gpctx->daemonize);
    if (!new_config) {
        sd_notifyf(0, "READY=1\n"
                   "STATUS=Running, %i service(s) configured"
                   " (failed to re-read config)\n",
                   gpctx->config->num_svcs);
        GPERROR("Error reading new configuration on SIGHUP; keeping old "
                "configuration instead!\n");
        return;
    }
    old_config = gpctx->config;
    gpctx->config = new_config;

    ret = init_sockets(gpctx, old_config);
    if (ret != 0) {
        exit(ret);
    }

    /* conditionally reload kernel interface */
    init_proc_nfsd(gpctx);

    free_config(&old_config);

    sd_notifyf(0, "READY=1\n"
               "STATUS=Running, %i service(s) configured\n",
               gpctx->config->num_svcs);
    GPDEBUG("New config loaded successfully.\n");
    return;
}

static void break_loop(verto_ctx *vctx, verto_ev *ev UNUSED)
{
    sd_notifyf(0, "STOPPING=1\nSTATUS=Signal received, stopping\n");
    GPDEBUG("Exiting after receiving a signal\n");
    verto_break(vctx);
}

void init_event_loop(struct gssproxy_ctx *gpctx)
{
    verto_ev *ev;

    gpctx->vctx = verto_default(NULL,
                                VERTO_EV_TYPE_IO |
                                VERTO_EV_TYPE_SIGNAL |
                                VERTO_EV_TYPE_TIMEOUT);
    if (!gpctx->vctx) {
        goto fail;
    }

    ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                          break_loop, SIGINT);
    if (!ev) {
        fprintf(stderr, "Failed to register SIGINT handler\n");
        goto fail;
    }
    ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                          break_loop, SIGTERM);
    if (!ev) {
        fprintf(stderr, "Failed to register SIGTERM handler\n");
        goto fail;
    }
    ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                          break_loop, SIGQUIT);
    if (!ev) {
        fprintf(stderr, "Failed to register SIGQUIT handler\n");
        goto fail;
    }
    ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                          VERTO_SIG_IGN, SIGPIPE);
    if (!ev) {
        fprintf(stderr, "Failed to register SIGPIPE handler\n");
        goto fail;
    }
    if (gpctx->userproxymode) {
        ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                              VERTO_SIG_IGN, SIGHUP);
    } else {
        ev = verto_add_signal(gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                              hup_handler, SIGHUP);
        if (ev) verto_set_private(ev, gpctx, NULL);
    }
    if (!ev) {
        fprintf(stderr, "Failed to register SIGHUP handler\n");
        goto fail;
    }

    return;

fail:
    if (gpctx->vctx) {
        verto_free(gpctx->vctx);
        gpctx->vctx = NULL;
    }
}

/* Schedule an event to run as soon as the event loop is started
 * This is also useful in debugging to know that all initialization
 * is done. */
static void delayed_init(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    struct gssproxy_ctx *gpctx = verto_get_private(ev);

    sd_notifyf(0, "READY=1\n"
	       "STATUS=Running, %i service(s) configured\n",
	       gpctx->config->num_svcs);

    GPDEBUG("Initialization complete.\n");

    idle_handler(gpctx);
}

int init_event_fini(struct gssproxy_ctx *gpctx)
{
    verto_ev *ev;

    ev = verto_add_timeout(gpctx->vctx, VERTO_EV_FLAG_NONE, delayed_init, 1);
    if (!ev) {
        fprintf(stderr, "Failed to register delayed_init event!\n");
        return EXIT_FAILURE;
    }
    verto_set_private(ev, gpctx, NULL);

    return 0;
}

static int try_init_proc_nfsd(void)
{
    char buf[] = "1";
    static bool poked = false;
    static bool warned_once = false;
    int fd = 1;
    int ret;

    if (poked) {
        return 0;
    }

    fd = open(LINUX_PROC_USE_GSS_PROXY_FILE, O_RDWR);
    if (fd == -1) {
        ret = errno;
        if (!warned_once) {
            GPDEBUG("Kernel doesn't support GSS-Proxy "
                    "(can't open %s: %d (%s))\n",
                    LINUX_PROC_USE_GSS_PROXY_FILE, ret, gp_strerror(ret));
            warned_once = true;
        }
        goto out;
    }

    ret = write(fd, buf, 1);
    if (ret != 1) {
        ret = errno;
        GPDEBUG("Failed to write to %s: %d (%s)\n",
                LINUX_PROC_USE_GSS_PROXY_FILE, ret, gp_strerror(ret));
        goto out;
    }

    GPDEBUG("Kernel GSS-Proxy support enabled\n");
    poked = true;
    ret = 0;

out:
    if (fd != -1) {
        close(fd);
    }
    return ret;
}

static void delayed_proc_nfsd(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    struct gssproxy_ctx *gpctx;
    int ret;

    gpctx = verto_get_private(ev);

    ret = try_init_proc_nfsd();
    if (ret == 0) {
        verto_del(gpctx->retry_proc_ev);
        gpctx->retry_proc_ev = NULL;
    }
}

int init_proc_nfsd(struct gssproxy_ctx *gpctx)
{
    bool enabled = false;
    int ret;

    /* check first if any service enabled kernel support */
    for (int i = 0; i < gpctx->config->num_svcs; i++) {
        if (gpctx->config->svcs[i]->kernel_nfsd) {
            enabled = true;
            break;
        }
    }

    if (!enabled) {
        goto out;
    }

    ret = try_init_proc_nfsd();
    if (ret == 0) {
        goto out;
    }

    /* failure, but the auth_rpcgss module might not be loaded yet */
    if (!gpctx->retry_proc_ev) {
        gpctx->retry_proc_ev = verto_add_timeout(gpctx->vctx,
                                                 VERTO_EV_FLAG_PERSIST,
                                                 delayed_proc_nfsd, 10 * 1000);
        if (!gpctx->retry_proc_ev) {
            fprintf(stderr, "Failed to register delayed_proc_nfsd event!\n");
        } else {
            verto_set_private(gpctx->retry_proc_ev, gpctx, NULL);
        }
    }

    return 1;

out:
    if (gpctx->retry_proc_ev) {
        verto_del(gpctx->retry_proc_ev);
        gpctx->retry_proc_ev = NULL;
    }
    return 0;
}

void write_pid(void)
{
    pid_t pid;
    FILE *f;
    int ret;

    pid = getpid();

    f = fopen(GP_PID_FILE, "w");
    if (!f) {
        ret = errno;
        GPDEBUG("Failed to open %s: %d (%s)\n",
                GP_PID_FILE, ret, gp_strerror(ret));
        return;
    }

    ret = fprintf(f, "%d\n", pid);
    if (ret <= 0) {
        GPDEBUG("Failed to write pid to %s\n", GP_PID_FILE);
    }

    ret = fclose(f);
    if (ret != 0) {
        ret = errno;
        GPDEBUG("Failed to close %s: %d (%s)\n",
                GP_PID_FILE, ret, gp_strerror(ret));
    }
}

int drop_privs(struct gp_config *cfg)
{
    char buf[2048];
    struct passwd *pw, pws;
    int ret;

#ifdef HAVE_CAP
    /* Retain capabilities when changing UID to non-zero.  We drop the ones we
     * don't need after the switch. */
    ret = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    if (ret) {
        ret = errno;
        GPDEBUG("Failed to set keep capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        return ret;
    }
#endif

    ret = getpwnam_r(cfg->proxy_user, &pws, buf, 2048, &pw);
    if (ret) {
        GPDEBUG("Failed to look up proxy user: '%s'! [%d:%s]\n",
                cfg->proxy_user, ret, gp_strerror(ret));
        return ret;
    }

    ret = initgroups(pw->pw_name, pw->pw_gid);
    if (ret) {
        GPDEBUG("Failed to set access credentials: [%d:%s]\n",
                ret, gp_strerror(ret));
        return ret;
    }

    ret = setgid(pw->pw_gid);
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to set group id to %d: [%d:%s]\n",
                pw->pw_gid, ret, gp_strerror(ret));
        return ret;
    }

    ret = setuid(pw->pw_uid);
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to set user id to %d: [%d:%s]\n",
                pw->pw_uid, ret, gp_strerror(ret));
        return ret;
    }

#ifdef HAVE_CAP
    /* Now drop the capabilities we don't need, and turn PR_SET_KEEPCAPS back
     * off. */
    ret = drop_caps();
    if (ret) {
        return ret;
    }

    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0)) {
        ret = errno;
        GPDEBUG("Failed to reset keep capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        return ret;
    }
#endif

    return 0;
}

#ifdef HAVE_CAP
/* Remove all capabilties from the process.  (In order to manipulate our
 * capability set, we need to have CAP_SETPCAP.) */
int clear_bound_caps()
{
    cap_t caps = NULL;
    cap_value_t cap = 0;
    const cap_value_t setpcap_list[] = { CAP_SETPCAP };
    int ret;

    caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        GPDEBUG("Failed to get current capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, setpcap_list, CAP_SET) == -1) {
        ret = errno;
        GPDEBUG("Failed to set CAP_SETPCAP in effective set: [%d:%s]\n", ret,
                gp_strerror(ret));
        goto done;
    }

    if (cap_set_proc(caps) == -1) {
        ret = errno;
        GPDEBUG("Failed to apply CAP_SETPCAP: [%d:%s]\n", ret,
                gp_strerror(ret));
        goto done;
    }

    /* Now that we have CAP_SETPCAP in the effective set, remove all other
     * capabilities. */
    while (CAP_IS_SUPPORTED(cap)) {
        if (cap_drop_bound(cap) != 0) {
            ret = errno;
            GPDEBUG("Failed to drop bounding set capability: [%d:%s]\n",
                    ret, gp_strerror(ret));
            goto done;
        }
        cap++;
    }
    ret = 0;

done:
    if (caps && cap_free(caps) == -1) {
        ret = errno;
        GPDEBUG("Failed to free capability state: [%d:%s]\n",
                ret, gp_strerror(ret));
    }
    return ret;
}

/* For program name matching, we need to have CAP_SYS_PTRACE in order to read
 * /proc/pid/exe.  Because we've set PR_SET_KEEPCAPS, every thread inherits
 * the process set of its parent, so we drop everything but CAP_SYS_PTRACE. */
int drop_caps()
{
    cap_t caps = NULL;
    int ret;
    const cap_value_t ptrace_list[] = { CAP_SYS_PTRACE };

    /* Completely drop the bounding set. */
    ret = clear_bound_caps();
    if (ret) {
        goto done;
    }

    ret = CAP_IS_SUPPORTED(CAP_SYS_PTRACE);
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to check if CAP_SYS_PTRACE is supported: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    } else if (!ret) {
        GPDEBUG("Capability CAPS_SYS_PTRACE is not supported\n");
        ret = EINVAL;
        goto done;
    }

    /* Now, make an empty capabilitiy set and put CAP_SYS_PTRACE in it. */
    caps = cap_init();
    if (caps == NULL) {
        ret = errno;
        GPDEBUG("Failed to init capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    }

    if (cap_set_flag(caps, CAP_PERMITTED, 1, ptrace_list, CAP_SET) == -1) {
        ret = errno;
        GPDEBUG("Failed to set permitted capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    }

    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, ptrace_list, CAP_SET) == -1) {
        ret = errno;
        GPDEBUG("Failed to set effective capabilities: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    }

    if (cap_set_proc(caps) == -1) {
        ret = errno;
        GPDEBUG("Failed to apply capability set: [%d:%s]\n",
                ret, gp_strerror(ret));
        goto done;
    }
    ret = 0;

done:
    if (caps && cap_free(caps) == -1) {
        ret = errno;
        GPDEBUG("Failed to free capability state: [%d:%s]\n",
                ret, gp_strerror(ret));
    }
    return ret;
}
#endif
