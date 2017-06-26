/* Copyright (C) 2011,2015 the GSS-PROXY contributors, see COPYING for license */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <locale.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include "gp_proxy.h"

void init_server(bool daemonize, int *wait_fd)
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
    closelog();
}

static void break_loop(verto_ctx *vctx, verto_ev *ev UNUSED)
{
    GPDEBUG("Exiting after receiving a signal\n");
    verto_break(vctx);
}

verto_ctx *init_event_loop(void)
{
    verto_ctx *vctx;
    verto_ev *ev;

    vctx = verto_default(NULL,
                         VERTO_EV_TYPE_IO |
                         VERTO_EV_TYPE_SIGNAL |
                         VERTO_EV_TYPE_TIMEOUT);
    if (!vctx) {
        return NULL;
    }

    ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST, break_loop, SIGINT);
    if (!ev) {
        verto_free(vctx);
        return NULL;
    }
    ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST, break_loop, SIGTERM);
    if (!ev) {
        verto_free(vctx);
        return NULL;
    }
    ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST, break_loop, SIGQUIT);
    if (!ev) {
        verto_free(vctx);
        return NULL;
    }
    ev = verto_add_signal(vctx, VERTO_EV_FLAG_PERSIST, VERTO_SIG_IGN, SIGPIPE);
    if (!ev) {
        verto_free(vctx);
        return NULL;
    }
    /* SIGHUP handler added in main */

    return vctx;
}

void init_proc_nfsd(struct gp_config *cfg)
{
    char buf[] = "1";
    bool enabled = false;
    int fd, ret;

    /* check first if any service enabled kernel support */
    for (int i = 0; i < cfg->num_svcs; i++) {
        if (cfg->svcs[i]->kernel_nfsd) {
            enabled = true;
            break;
        }
    }

    if (!enabled) {
        return;
    }

    fd = open(LINUX_PROC_USE_GSS_PROXY_FILE, O_RDWR);
    if (fd == -1) {
        ret = errno;
        GPDEBUG("Kernel doesn't support GSS-Proxy (can't open %s: %d (%s))\n",
                LINUX_PROC_USE_GSS_PROXY_FILE, ret, gp_strerror(ret));
        goto fail;
    }

    ret = write(fd, buf, 1);
    if (ret != 1) {
        ret = errno;
        GPDEBUG("Failed to write to %s: %d (%s)\n",
                LINUX_PROC_USE_GSS_PROXY_FILE, ret, gp_strerror(ret));
        close(fd);
        goto fail;
    }

    close(fd);
    return;
fail:
    GPDEBUG("Problem with kernel communication!  NFS server will not work\n");
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

    if (cfg->proxy_user == NULL) {
        /* not dropping privs */
        return 0;
    }

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

    return 0;
}
