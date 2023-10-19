/* Copyright (C) 2022 the GSS-PROXY contributors, see COPYING for license */

#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "gp_proxy.h"

static void idle_terminate(verto_ctx *vctx, verto_ev *ev)
{
    struct gssproxy_ctx *gpctx = verto_get_private(ev);

    sd_notifyf(0, "STOPPING=1\nSTATUS=Idle for %ld seconds, stopping\n",
               (long)gpctx->term_timeout/1000);

    GPDEBUG("Terminating, after idling for %ld seconds!\n",
            (long)gpctx->term_timeout/1000);
    verto_break(vctx);
}

void idle_handler(struct gssproxy_ctx *gpctx)
{
    /* we've been called, this means some event just fired,
     * restart the timeout handler */

    if (gpctx->userproxymode == false || gpctx->term_timeout == 0) {
        /* self termination is disabled */
        return;
    }

    verto_del(gpctx->term_ev);

    /* Add self-termination timeout */
    gpctx->term_ev = verto_add_timeout(gpctx->vctx, VERTO_EV_FLAG_NONE,
                                       idle_terminate, gpctx->term_timeout);
    if (!gpctx->term_ev) {
        GPDEBUG("Failed to register timeout event!\n");
    }
    verto_set_private(gpctx->term_ev, gpctx, NULL);
}

void gp_activity_accounting(struct gssproxy_ctx *gpctx,
                            ssize_t rb, ssize_t wb)
{
    time_t now = time(NULL);

    if (rb) {
        /* Gssproxy received some request */
        gpctx->readstats += rb;
        GPDEBUGN(GP_INFO_DEBUG_LVL, "Total received bytes: %ld\n",
                 (long)gpctx->readstats);

        /* receiving bytes is also a sign of activity,
         * reset idle event */
        idle_handler(gpctx);

        GPDEBUGN(GP_INFO_DEBUG_LVL, "Idle for: %ld seconds\n",
                 now - gpctx->last_activity);
        gpctx->last_activity = now;
    }

    if (wb) {
        gpctx->writestats += wb;
        GPDEBUGN(GP_INFO_DEBUG_LVL, "Total sent bytes: %ld\n",
                 (long)gpctx->writestats);

        /* sending bytes is also a sign of activity, but we send
         * bytes only in response to requests and this is already
         * captured by a previous read event, just update the
         * last_activity counter to have a more precise info messgae
         * on the following read */
        gpctx->last_activity = now;
    }
}

#define MAX_K5_EVENTS 10
static struct k5tracer {
    pthread_t tid;
    int fd;
} *k5tracer = NULL;

static void *k5tracer_thread(void *pvt UNUSED)
{
    struct epoll_event ev, events[MAX_K5_EVENTS];
    int num, epollfd;

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    fprintf(stderr, "k5tracer_thread started!\n");
    fflush(stderr);

    epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (epollfd == -1) {
        fprintf(stderr, "k5tracer_thread, epoll_create1 failed\n");
        fflush(stderr);
        pthread_exit(NULL);
    }

    ev.events = EPOLLIN;
    ev.data.fd = k5tracer->fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, k5tracer->fd, &ev) == -1) {
        fprintf(stderr, "k5tracer_thread, epoll_ctl failed\n");
        fflush(stderr);
        pthread_exit(NULL);
    }


    for (;;) {
        num = epoll_wait(epollfd, events, MAX_K5_EVENTS, -1);
        if (num == -1) {
            fprintf(stderr, "k5tracer_thread, epoll_wait failed (%d)\n",
                            errno);
            fflush(stderr);
            pthread_exit(NULL);
        }

        for (int i = 0; i < num; i++) {
            if (events[i].events & EPOLLIN) {
                char buf[512];
                size_t pos = 0;
                ssize_t rn;
                size_t wn;

                for (;;) {
                    rn = read(events[i].data.fd, buf, 512);
                    if (rn == -1) {
                        if (errno != EAGAIN && errno != EINTR ) {
                            fprintf(stderr, "k5tracer_thread, "
                                            "fatal error on fd %d %d\n",
                                            events[i].data.fd, errno);
                            break;
                        }
                        rn = 0;
                    }
                    if (rn == 0) {
                        /* done, getting input */
                        break;
                    }
                    /* let's hope all gets written, but if not we just
                     * missed some debugging output and thatis ok, in
                     * the very unlikely case it happens */
                    while (rn > 0) {
                        wn = fwrite(buf + pos, 1, rn, stderr);
                        if (wn == 0) break;
                        rn -= wn;
                        pos += rn;
                    }
                }
            }
        }
        fflush(stderr);
    }
}

void free_k5tracer(void)
{
    if (k5tracer == NULL) return;

    if (k5tracer->fd > 0) {
        close(k5tracer->fd);
    }
    safefree(k5tracer);
}

char *tracing_file_name = NULL;

/* if action == 1 activate KRB5 tracing bridge.
 * if action == 0 deactivate it */
void gp_krb5_tracing_setup(int action)
{
    pthread_attr_t attr;
    int ret;

    if (action != 0 && action != 1) {
        GPDEBUGN(3, "%s: Unknown action %d\n", __func__, action);
        return;
    }

    if (action == 0) {
        if (k5tracer) {
            pthread_cancel(k5tracer->tid);
            pthread_join(k5tracer->tid, NULL);
            unsetenv("KRB5_TRACE");
        }
        return;
    }

    /* activate only once */
    if (k5tracer != NULL) return;

    k5tracer = calloc(1, sizeof(struct k5tracer));
    if (k5tracer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* this name is predictable, but we always unlink it before
     * creating a new one with permission only for the current
     * user. A race between unilnk and mkfifo will cause failure
     * and we'll never open the file that raced us */
    if (tracing_file_name == NULL) {
        ret = asprintf(&tracing_file_name,
                       "/tmp/krb5.tracing.%ld", (long)getpid());
        if (ret == -1) {
            ret = errno;
            goto done;
        }
    }

    ret = unlink(tracing_file_name);
    if (ret == -1 && errno != ENOENT) {
        ret = errno;
        GPDEBUGN(3, "%s: unlink(%s) failed\n", __func__, tracing_file_name);
        goto done;
    }

    ret = mkfifo(tracing_file_name, 0600);
    if (ret == -1) {
        ret = errno;
        GPDEBUGN(3, "%s: mkfifo(%s) failed\n", __func__, tracing_file_name);
        goto done;
    }

    k5tracer->fd = open(tracing_file_name, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (k5tracer->fd == -1) {
        ret = errno;
        GPDEBUGN(3, "%s: open(%s) failed\n", __func__, tracing_file_name);
        goto done;
    } else if (k5tracer->fd <= 2) {
        /* we do not expect stdio to be closed because we need to use it
         * to forward the tracing, if the fd return is smaller than stderr
         * consider stdio messed up and just ignore tracing */
        ret = EINVAL;
        GPDEBUGN(3, "%s: open(%s) returned fd too low: %d",
                    __func__, tracing_file_name, k5tracer->fd);
        close(k5tracer->fd);
        k5tracer->fd = 0;
        goto done;
    }

    ret = pthread_attr_init(&attr);
    if (ret) {
        GPDEBUGN(3, "%s: pthread_attr_init failed: %d", __func__, ret);
        goto done;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (ret) {
        GPDEBUGN(3, "%s: pthread_attr_setdetachstate: %d", __func__, ret);
    }

    ret = pthread_create(&k5tracer->tid, &attr, k5tracer_thread, NULL);
    if (ret) {
        pthread_attr_destroy(&attr);

        GPDEBUGN(3, "%s: pthread_create failed: %d", __func__, ret);
        goto done;
    }

    pthread_attr_destroy(&attr);
    setenv("KRB5_TRACE", tracing_file_name, 1);

    ret = 0;

done:
    if (ret) {
        char errstr[128]; /* reasonable error str length */
        GPDEBUGN(3, "%s: Failed to set up krb5 tracing thread: [%s](%d)\n",
                    __func__, strerror_r(ret, errstr, 128), ret);
        free_k5tracer();
    }
    return;
}

void gp_krb5_fini_tracing(void)
{
    if (tracing_file_name) {
        /* just in case */
        gp_krb5_tracing_setup(0);
        /* remove this one if there */
        unlink(tracing_file_name);
    }
}
