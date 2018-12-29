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

#ifdef HAVE_CAP

#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#endif

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
    static int poked = 0;

    /* check first if any service enabled kernel support */
    for (int i = 0; i < cfg->num_svcs; i++) {
        if (cfg->svcs[i]->kernel_nfsd) {
            enabled = true;
            break;
        }
    }

    if (!enabled || poked) {
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

    poked = 1;
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
