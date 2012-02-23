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
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include "gp_proxy.h"

#define DEFAULT_WORKER_THREADS_NUM 5

#define GP_QUERY_IN 0
#define GP_QUERY_OUT 1
#define GP_QUERY_ERR 2

struct gp_query {
    struct gp_query *next;

    struct gp_conn *conn;
    uint8_t *buffer;
    size_t buflen;

    int status;
};

struct gp_thread {
    struct gp_thread *prev;
    struct gp_thread *next;
    struct gp_workers *pool;
    pthread_t tid;

    struct gp_query *query;
    pthread_mutex_t cond_mutex;
    pthread_cond_t cond_wakeup;
};

struct gp_workers {
    pthread_mutex_t lock;
    struct gssproxy_ctx *gpctx;
    bool shutdown;
    struct gp_query *wait_list;
    struct gp_query *reply_list;
    struct gp_thread *free_list;
    struct gp_thread *busy_list;
    int num_threads;
    int sig_pipe[2];
};

static void *gp_worker_main(void *pvt);
static void gp_handle_query(struct gp_workers *w, struct gp_query *q);
static void gp_handle_reply(verto_ctx *vctx, verto_ev *ev);

/** DISPATCHER FUNCTIONS **/

int gp_workers_init(struct gssproxy_ctx *gpctx)
{
    struct gp_workers *w;
    struct gp_thread *t;
    pthread_attr_t attr;
    verto_ev *ev;
    int vflags;
    int ret;
    int i;

    w = calloc(1, sizeof(struct gp_workers));
    if (!w) {
        return ENOMEM;
    }
    w->gpctx = gpctx;

    /* init global queue mutex */
    ret = pthread_mutex_init(&w->lock, NULL);
    if (ret) {
        free(w);
        return ENOMEM;
    }

    if (gpctx->config->num_workers > 0) {
        w->num_threads = gpctx->config->num_workers;
    } else {
        w->num_threads = DEFAULT_WORKER_THREADS_NUM;
    }

    /* make thread joinable (portability) */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    /* init all workers */
    for (i = 0; i < w->num_threads; i++) {
        t = calloc(1, sizeof(struct gp_thread));
        if (!t) {
            ret = -1;
            goto done;
        }
        t->pool = w;
        ret = pthread_cond_init(&t->cond_wakeup, NULL);
        if (ret) {
            goto done;
        }
        ret = pthread_mutex_init(&t->cond_mutex, NULL);
        if (ret) {
            goto done;
        }
        ret = pthread_create(&t->tid, &attr, gp_worker_main, t);
        if (ret) {
            goto done;
        }
        LIST_ADD(w->free_list, t);
    }

    /* add wakeup pipe, so that threads can hand back replies to the
     * dispatcher */
    ret = pipe2(w->sig_pipe, O_NONBLOCK | O_CLOEXEC);
    if (ret == -1) {
        goto done;
    }

    vflags = VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ;
    ev = verto_add_io(gpctx->vctx, vflags, gp_handle_reply, w->sig_pipe[0]);
    if (!ev) {
        ret = -1;
        goto done;
    }
    verto_set_private(ev, w, NULL);

    gpctx->workers = w;
    ret = 0;

done:
    if (ret) {
        gp_workers_free(w);
    }
    return ret;
}

void gp_workers_free(struct gp_workers *w)
{
    struct gp_thread *t;
    void *retval;

    /* ======> POOL LOCK */
    pthread_mutex_lock(&w->lock);

    w->shutdown = true;

    /* <====== POOL LOCK */
    pthread_mutex_unlock(&w->lock);

    /* we do not run the following operations within
     * the lock, or deadlocks may arise for threads
     * that are just finishing doing some work */

    /* we guarantee nobody is touching these lists by
     * preventing workers from touching the free/busy
     * lists when a 'shutdown' is in progress */

    while (w->free_list) {
        /* pick threads one by one */
        t = w->free_list;
        LIST_DEL(w->free_list, t);

        /* wake up threads, then join them */
        /* ======> COND_MUTEX */
        pthread_mutex_lock(&t->cond_mutex);
        pthread_cond_signal(&t->cond_wakeup);
        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&t->cond_mutex);

        pthread_join(t->tid, &retval);

        pthread_mutex_destroy(&t->cond_mutex);
        pthread_cond_destroy(&t->cond_wakeup);
        free(t);
    }

    /* do the same with the busy list */
    while (w->busy_list) {
        /* pick threads one by one */
        t = w->busy_list;
        LIST_DEL(w->free_list, t);

        /* wake up threads, then join them */
        /* ======> COND_MUTEX */
        pthread_mutex_lock(&t->cond_mutex);
        pthread_cond_signal(&t->cond_wakeup);
        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&t->cond_mutex);

        pthread_join(t->tid, &retval);

        pthread_mutex_destroy(&t->cond_mutex);
        pthread_cond_destroy(&t->cond_wakeup);
        free(t);
    }

    close(w->sig_pipe[0]);
    close(w->sig_pipe[1]);

    pthread_mutex_destroy(&w->lock);

    free(w);
}

static void gp_query_assign(struct gp_workers *w, struct gp_query *q)
{
    struct gp_thread *t = NULL;

    /* then either find a free thread or queue in the wait list */

    /* ======> POOL LOCK */
    pthread_mutex_lock(&w->lock);
    if (w->free_list) {
        t = w->free_list;
        LIST_DEL(w->free_list, t);
        LIST_ADD(w->busy_list, t);
    }
    /* <====== POOL LOCK */
    pthread_mutex_unlock(&w->lock);

    if (t) {
        /* found free thread, assign work */

        /* ======> COND_MUTEX */
        pthread_mutex_lock(&t->cond_mutex);

        /* hand over the query */
        t->query = q;
        pthread_cond_signal(&t->cond_wakeup);

        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&t->cond_mutex);

    } else {

        /* all threads are busy, store in wait list */

        /* only the dispatcher handles wait_list
        *  so we do not need to lock around it */
        q->next = w->wait_list;
        w->wait_list = q;
    }
}

static void gp_query_free(struct gp_query *q, bool free_buffer)
{
    if (!q) {
        return;
    }

    if (free_buffer) {
        free(q->buffer);
    }

    free(q);
}

int gp_query_new(struct gp_workers *w, struct gp_conn *conn,
                 uint8_t *buffer, size_t buflen)
{
    struct gp_query *q;

    /* create query struct */
    q = calloc(1, sizeof(struct gp_query));
    if (!q) {
        return ENOMEM;
    }

    q->conn = conn;
    q->buffer = buffer;
    q->buflen = buflen;

    gp_query_assign(w, q);

    return 0;
}

static void gp_handle_reply(verto_ctx *vctx, verto_ev *ev)
{
    struct gp_workers *w;
    struct gp_query *q = NULL;
    char dummy;
    int ret;

    w = verto_get_private(ev);

    /* first read out the dummy so the pipe doesn't get clogged */
    ret = read(w->sig_pipe[0], &dummy, 1);
    if (ret) {
        /* ignore errors */
    }

    /* grab a query reply if any */
    if (w->reply_list) {
        /* ======> POOL LOCK */
        pthread_mutex_lock(&w->lock);

        if (w->reply_list != NULL) {
            q = w->reply_list;
            w->reply_list = q->next;
        }

        /* <====== POOL LOCK */
        pthread_mutex_unlock(&w->lock);
    }

    if (q) {
        switch (q->status) {
        case GP_QUERY_IN:
            /* ?! fallback and kill client conn */
        case GP_QUERY_ERR:
            gp_conn_free(q->conn);
            gp_query_free(q, true);
            break;

        case GP_QUERY_OUT:
            gp_socket_send_data(vctx, q->conn, q->buffer, q->buflen);
            gp_query_free(q, false);
            break;
        }
    }

    /* while we are at it, check if there is anything in the wait list
     * we need to process, as one thread just got free :-) */

    q = NULL;

    if (w->wait_list) {
        /* only the dispatcher handles wait_list
        *  so we do not need to lock around it */
        if (w->wait_list) {
            q = w->wait_list;
            w->wait_list = q->next;
            q->next = NULL;
        }
    }

    if (q) {
        gp_query_assign(w, q);
    }
}


/** WORKER THREADS **/

static void *gp_worker_main(void *pvt)
{
    struct gp_thread *t = (struct gp_thread *)pvt;
    struct gp_query *q = NULL;
    char dummy = 0;
    int ret;

    while (!t->pool->shutdown) {

        /* ======> COND_MUTEX */
        pthread_mutex_lock(&t->cond_mutex);
        while (t->query == NULL) {
            /* wait for next query */
            pthread_cond_wait(&t->cond_wakeup, &t->cond_mutex);
            if (t->pool->shutdown) {
                pthread_exit(NULL);
            }
        }

        /* grab the query off the shared pointer */
        q = t->query;
        t->query = NULL;

        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&t->cond_mutex);

        /* handle the client request */
        gp_handle_query(t->pool, q);

        /* now get lock on main queue, to play with the reply list */
        /* ======> POOL LOCK */
        pthread_mutex_lock(&t->pool->lock);

        /* put back query so that dispatcher can send reply */
        q->next = t->pool->reply_list;
        t->pool->reply_list = q;

        /* add us back to the free list but only if we are not
         * shutting down */
        if (!t->pool->shutdown) {
            LIST_DEL(t->pool->busy_list, t);
            LIST_ADD(t->pool->free_list, t);
        }

        /* <====== POOL LOCK */
        pthread_mutex_unlock(&t->pool->lock);

        /* and wake up dispatcher so it will handle it */
        ret = write(t->pool->sig_pipe[1], &dummy, 1);
        if (ret == -1) {
            syslog(LOG_ERR, "Failed to signal dispatcher!");
        }
    }

    pthread_exit(NULL);
}

static void gp_handle_query(struct gp_workers *w, struct gp_query *q)
{
    struct gp_service *gpsvc;
    uint8_t *buffer;
    size_t buflen;
    int ret;

    /* find service */
    gpsvc = gp_creds_match_conn(w->gpctx, q->conn);
    if (!gpsvc) {
        q->status = GP_QUERY_ERR;
        return;
    }

    ret = gp_rpc_process_call(w->gpctx, gpsvc,
                              q->buffer, q->buflen,
                              &buffer, &buflen);
    if (ret) {
        q->status = GP_QUERY_ERR;
    } else {
        q->status = GP_QUERY_OUT;
        free(q->buffer);
        q->buffer = buffer;
        q->buflen = buflen;
    }
}

