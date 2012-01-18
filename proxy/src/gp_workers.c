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
#include "gp_utils.h"

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
    struct gp_workers *pool;
    pthread_t tid;

    /* if query is assigned, then the thread is busy */
    struct gp_query *query;
    pthread_mutex_t cond_mutex;
    pthread_cond_t cond_wakeup;
};

struct gp_workers {
    pthread_mutex_t lock;
    bool shutdown;
    struct gp_query *wait_list;
    struct gp_query *reply_list;
    struct gp_thread *threads;
    int num_threads;
    int sig_pipe[2];
};

static void *gp_worker_main(void *pvt);
static void gp_handle_query(struct gp_workers *w, struct gp_query *q);
static void gp_handle_reply(verto_ctx *vctx, verto_ev *ev);

/** DISPATCHER FUNCTIONS **/

struct gp_workers *gp_workers_init(verto_ctx *vctx, struct gp_config *cfg)
{
    struct gp_workers *w;
    pthread_attr_t attr;
    verto_ev *ev;
    int vflags;
    int ret;
    int i;

    w = calloc(1, sizeof(struct gp_workers));
    if (!w) {
        return NULL;
    }

    /* init global queue mutex */
    ret = pthread_mutex_init(&w->lock, NULL);
    if (ret) {
        free(w);
        return NULL;
    }

    if (cfg->num_workers > 0) {
        w->num_threads = cfg->num_workers;
    } else {
        w->num_threads = DEFAULT_WORKER_THREADS_NUM;
    }

    w->threads = calloc(w->num_threads, sizeof(struct gp_thread));
    if (!w->threads) {
        ret = -1;
        goto done;
    }

    /* make thread joinable (portability) */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    /* init all workers */
    for (i = 0; i < w->num_threads; i++) {
        ret = pthread_cond_init(&w->threads[i].cond_wakeup, NULL);
        if (ret) {
            goto done;
        }
        ret = pthread_mutex_init(&w->threads[i].cond_mutex, NULL);
        if (ret) {
            goto done;
        }
        ret = pthread_create(&w->threads[i].tid, &attr,
                             gp_worker_main, &w->threads[i]);
        if (ret) {
            goto done;
        }
        w->threads[i].pool = w;
    }

    /* add wakeup pipe, so that threads can hand back replies to the
     * dispatcher */
    ret = pipe2(w->sig_pipe, O_NONBLOCK | O_CLOEXEC);
    if (ret == -1) {
        goto done;
    }

    vflags = VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ;
    ev = verto_add_io(vctx, vflags, gp_handle_reply, w->sig_pipe[0]);
    if (!ev) {
        ret = -1;
        goto done;
    }
    verto_set_private(ev, w, NULL);

    ret = 0;

done:
    if (ret) {
        gp_workers_free(w);
    }
    return w;
}

void gp_workers_free(struct gp_workers *w)
{
    int ret;
    int i;
    void *retval;

    ret = pthread_mutex_lock(&w->lock);
    if (ret) {
        syslog(LOG_CRIT, "Couldn't get mutex!");
        return;
    }

    w->shutdown = true;

    ret = pthread_mutex_unlock(&w->lock);
    if (ret) {
        syslog(LOG_CRIT, "Can't release mutex?!");
        return;
    }

    if (w->threads) {
        for (i = 0; i < w->num_threads; i++) {
            /* wake up threads, then join them */
            /* ======> COND_MUTEX */
            pthread_mutex_lock(&w->threads[i].cond_mutex);
            pthread_cond_signal(&w->threads[i].cond_wakeup);
            /* <====== COND_MUTEX */
            pthread_mutex_unlock(&w->threads[i].cond_mutex);

            ret = pthread_join(w->threads[i].tid, &retval);
        }

        free(w->threads);
        w->threads = NULL;
    }

    ret = pthread_mutex_destroy(&w->lock);
    if (ret) {
        syslog(LOG_CRIT, "Failed to destroy mutex?!");
        return;
    }

    free(w);
}

static void gp_query_assign(struct gp_workers *w, struct gp_query *q)
{
    int i;
    /* then either find a free thread or queue in the wait list */

    for (i = 0; q != NULL && i < w->num_threads; i++) {
        if (w->threads[i].query != NULL) continue;

        /* ======> COND_MUTEX */
        pthread_mutex_lock(&w->threads[i].cond_mutex);

        if (w->threads[i].query == NULL) {
            /* hand over the query */
            w->threads[i].query = q;
            q = NULL;
            pthread_cond_signal(&w->threads[i].cond_wakeup);
        }

        /* <====== COND_MUTEX */
        pthread_mutex_unlock(&w->threads[i].cond_mutex);
    }

    if (q) {
        /* all threads are busy, store in wait list */

        /* only the dispatcher handles wait_list
        *  so we do not need to lock around it */
        q->next = w->wait_list;
        w->wait_list = q;
        q = NULL;
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

        /* wait for next query */
        if (t->query == NULL) {
            /* ======> COND_MUTEX */
            pthread_mutex_lock(&t->cond_mutex);
            while (t->query == NULL) {
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
        }

        /* handle the client request */
        gp_handle_query(t->pool, q);

        /* now get lock on main queue, to play with the reply list */
        /* ======> POOL LOCK */
        pthread_mutex_lock(&t->pool->lock);

        /* put back query so that dispatcher can send reply */
        q->next = t->pool->reply_list;
        t->pool->reply_list = q;

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
    /* TODO */

    free(q->buffer);
    q->buffer = strdup("WHATS UP?");
    q->buflen = strlen(q->buffer);
    q->status = GP_QUERY_OUT;
}

