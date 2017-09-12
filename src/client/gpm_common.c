/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <sys/timerfd.h>

#define FRAGMENT_BIT (1 << 31)

#define RESPONSE_TIMEOUT 15
#define MAX_TIMEOUT_RETRY 3

struct gpm_ctx {
    pthread_mutex_t lock;
    int fd;

    /* these are only meaningful if fd != -1 */
    pid_t pid;
    uid_t uid;
    gid_t gid;

    int next_xid;

    int epollfd;
    int timerfd;
};

/* a single global struct is not particularly efficient,
 * but will do for now */
struct gpm_ctx gpm_global_ctx;

pthread_once_t gpm_init_once_control = PTHREAD_ONCE_INIT;

static void gpm_init_once(void)
{
    pthread_mutexattr_t attr;
    unsigned int seedp;

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&gpm_global_ctx.lock, &attr);

    gpm_global_ctx.fd = -1;
    gpm_global_ctx.epollfd = -1;
    gpm_global_ctx.timerfd = -1;

    seedp = time(NULL) + getpid() + pthread_self();
    gpm_global_ctx.next_xid = rand_r(&seedp);

    pthread_mutexattr_destroy(&attr);
}

static int get_pipe_name(char *name)
{
    const char *socket;
    int ret;

    socket = gp_getenv("GSSPROXY_SOCKET");
    if (!socket) {
        socket = GP_SOCKET_NAME;
    }

    ret = snprintf(name, PATH_MAX, "%s", socket);
    if (ret < 0 || ret >= PATH_MAX) {
        return ENAMETOOLONG;
    }

    return 0;
}

static int gpm_open_socket(struct gpm_ctx *gpmctx)
{
    struct sockaddr_un addr = {0};
    char name[PATH_MAX];
    int ret;
    unsigned flags;
    int fd = -1;

    ret = get_pipe_name(name);
    if (ret) {
        return ret;
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, name, sizeof(addr.sun_path)-1);
    addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        ret = errno;
        goto done;
    }

    ret = fcntl(fd, F_GETFD, &flags);
    if (ret != 0) {
        ret = errno;
        goto done;
    }

    ret = fcntl(fd, F_SETFD, flags | O_NONBLOCK);
    if (ret != 0) {
        ret = errno;
        goto done;
    }

    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        ret = errno;
    }

done:
    if (ret) {
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
    }
    gpmctx->fd = fd;
    gpmctx->pid = getpid();
    gpmctx->uid = geteuid();
    gpmctx->gid = getegid();
    return ret;
}

static void gpm_close_socket(struct gpm_ctx *gpmctx)
{
    int ret;

    do {
        ret = close(gpmctx->fd);
        /* in theory we should retry to close() on EINTR,
         * but on same system the fd will be invalid after
         * close() has been called, so closing again may
         * cause a race with another thread that just happend
         * to open an unrelated file descriptor.
         * So until POSIX finally amends language around close()
         * and at least the Linux kernel changes its behavior,
         * it is better to risk a leak than closing an unrelated
         * file descriptor */
        ret = 0;
    } while (ret == EINTR);

    gpmctx->fd = -1;
}

static int gpm_grab_sock(struct gpm_ctx *gpmctx)
{
    int ret;
    pid_t p;
    uid_t u;
    gid_t g;

    ret = pthread_mutex_lock(&gpmctx->lock);
    if (ret) {
        return ret;
    }

    /* Detect fork / setresuid and friends */
    p = getpid();
    u = geteuid();
    g = getegid();

    if (gpmctx->fd != -1 &&
        (p != gpmctx->pid || u != gpmctx->uid || g != gpmctx->gid)) {
        gpm_close_socket(gpmctx);
    }

    if (gpmctx->fd == -1) {
        ret = gpm_open_socket(gpmctx);
    }

    pthread_mutex_unlock(&gpmctx->lock);
    return ret;
}

static int gpm_release_sock(struct gpm_ctx *gpmctx)
{
    return pthread_mutex_unlock(&gpmctx->lock);
}

static void gpm_timer_close(struct gpm_ctx *gpmctx)
{
    if (gpmctx->timerfd < 0) {
        return;
    }

    close(gpmctx->timerfd);
    gpmctx->timerfd = -1;
}

static int gpm_timer_setup(struct gpm_ctx *gpmctx, int timeout_seconds)
{
    int ret;
    struct itimerspec its;

    if (gpmctx->timerfd >= 0) {
        gpm_timer_close(gpmctx);
    }

    gpmctx->timerfd = timerfd_create(CLOCK_MONOTONIC,
                                     TFD_NONBLOCK | TFD_CLOEXEC);
    if (gpmctx->timerfd < 0) {
        return errno;
    }

    its.it_interval.tv_sec = timeout_seconds;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = timeout_seconds;
    its.it_value.tv_nsec = 0;

    ret = timerfd_settime(gpmctx->timerfd, 0, &its, NULL);
    if (ret) {
        ret = errno;
        gpm_timer_close(gpmctx);
        return ret;
    }

    return 0;
}

static void gpm_epoll_close(struct gpm_ctx *gpmctx)
{
    if (gpmctx->epollfd < 0) {
        return;
    }

    close(gpmctx->epollfd);
    gpmctx->epollfd = -1;
}

static int gpm_epoll_setup(struct gpm_ctx *gpmctx)
{
    struct epoll_event ev;
    int ret;

    if (gpmctx->epollfd >= 0) {
        gpm_epoll_close(gpmctx);
    }

    gpmctx->epollfd = epoll_create1(EPOLL_CLOEXEC);
    if (gpmctx->epollfd == -1) {
        return errno;
    }

    /* Add timer */
    ev.events = EPOLLIN;
    ev.data.fd = gpmctx->timerfd;
    ret = epoll_ctl(gpmctx->epollfd, EPOLL_CTL_ADD, gpmctx->timerfd, &ev);
    if (ret == -1) {
        ret = errno;
        gpm_epoll_close(gpmctx);
        return ret;
    }

    return ret;
}

static int gpm_epoll_wait(struct gpm_ctx *gpmctx, uint32_t event_flags)
{
    int ret;
    int epoll_ret;
    struct epoll_event ev;
    struct epoll_event events[2];
    uint64_t timer_read;

    if (gpmctx->epollfd < 0) {
        ret = gpm_epoll_setup(gpmctx);
        if (ret)
            return ret;
    }

    ev.events = event_flags;
    ev.data.fd = gpmctx->fd;
    epoll_ret = epoll_ctl(gpmctx->epollfd, EPOLL_CTL_ADD, gpmctx->fd, &ev);
    if (epoll_ret == -1) {
        ret = errno;
        gpm_epoll_close(gpmctx);
        return ret;
    }

    do {
        epoll_ret = epoll_wait(gpmctx->epollfd, events, 2, -1);
    } while (epoll_ret < 0 && errno == EINTR);

    if (epoll_ret < 0) {
        /* Error while waiting that isn't EINTR */
        ret = errno;
        gpm_epoll_close(gpmctx);
    } else if (epoll_ret == 0) {
        /* Shouldn't happen as timeout == -1; treat it like a timeout
         * occurred. */
        ret = ETIMEDOUT;
        gpm_epoll_close(gpmctx);
    } else if (epoll_ret == 1 && events[0].data.fd == gpmctx->timerfd) {
        /* Got an event which is only our timer */
        ret = read(gpmctx->timerfd, &timer_read, sizeof(uint64_t));
        if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* In the case when reading from the timer failed, don't hide the
             * timer error behind ETIMEDOUT such that it isn't retried */
            ret = errno;
        } else {
            /* If ret == 0, then we definitely timed out. Else, if ret == -1
             * and errno == EAGAIN or errno == EWOULDBLOCK, we're in a weird
             * edge case where epoll thinks the timer can be read, but it
             * is blocking more; treat it like a TIMEOUT and retry, as
             * nothing around us would handle EAGAIN from timer and retry
             * it. */
            ret = ETIMEDOUT;
        }
        gpm_epoll_close(gpmctx);
    } else {
        /* If ret == 2, then we ignore the timerfd; that way if the next
         * operation cannot be performed immediately, we timeout and retry.
         * If ret == 1 and data.fd == gpmctx->fd, return 0. */
        ret = 0;
    }

    epoll_ret = epoll_ctl(gpmctx->epollfd, EPOLL_CTL_DEL, gpmctx->fd, NULL);
    if (epoll_ret == -1) {
        /* If we previously had an error, expose that error instead of
         * clobbering it with errno; else if no error, then assume it is
         * better to notify of the error deleting the event than it is
         * to continue. */
        if (ret == 0)
            ret = errno;
        gpm_epoll_close(gpmctx);
    }

    return ret;
}

static int gpm_retry_socket(struct gpm_ctx *gpmctx)
{
    gpm_epoll_close(gpmctx);
    gpm_close_socket(gpmctx);
    return gpm_open_socket(gpmctx);
}

/* must be called after the lock has been grabbed */
static int gpm_send_buffer(struct gpm_ctx *gpmctx,
                           char *buffer, uint32_t length)
{
    uint32_t size;
    ssize_t wn;
    size_t pos;
    bool retry;
    int ret;

    if (length > MAX_RPC_SIZE) {
        return EINVAL;
    }

    size = length | FRAGMENT_BIT;
    size = htonl(size);

    retry = false;
    do {
        do {
            ret = gpm_epoll_wait(gpmctx, EPOLLOUT);
            if (ret != 0) {
                goto done;
            }

            ret = 0;
            wn = write(gpmctx->fd, &size, sizeof(uint32_t));
            if (wn == -1) {
                ret = errno;
            }
        } while (ret == EINTR);
        if (wn != 4) {
            /* reopen and retry once */
            if (retry == false) {
                ret = gpm_retry_socket(gpmctx);
                if (ret == 0) {
                    retry = true;
                    continue;
                }
            } else {
                ret = EIO;
            }
            goto done;
        }
        retry = false;
    } while (retry);

    pos = 0;
    while (length > pos) {
        ret = gpm_epoll_wait(gpmctx, EPOLLOUT);
        if (ret) {
            goto done;
        }

        wn = write(gpmctx->fd, buffer + pos, length - pos);
        if (wn == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            ret = errno;
            goto done;
        }
        pos += wn;
    }

    ret = 0;

done:
    if (ret) {
        /* on errors we can only close the fd and return */
        gpm_close_socket(gpmctx);
    }
    return ret;
}

/* must be called after the lock has been grabbed */
static int gpm_recv_buffer(struct gpm_ctx *gpmctx,
                           char **buffer, uint32_t *length)
{
    uint32_t size;
    ssize_t rn;
    size_t pos;
    int ret;

    do {
        ret = gpm_epoll_wait(gpmctx, EPOLLIN);
        if (ret) {
            goto done;
        }

        ret = 0;
        rn = read(gpmctx->fd, &size, sizeof(uint32_t));
        if (rn == -1) {
            ret = errno;
        }
    } while (ret == EINTR);
    if (rn != 4) {
        ret = EIO;
        goto done;
    }

    *length = ntohl(size);
    *length &= ~FRAGMENT_BIT;

    if (*length > MAX_RPC_SIZE) {
        ret = EMSGSIZE;
        goto done;
    }

    *buffer = malloc(*length);
    if (*buffer == NULL) {
        ret = ENOMEM;
        goto done;
    }

    pos = 0;
    while (*length > pos) {
        ret = gpm_epoll_wait(gpmctx, EPOLLIN);
        if (ret) {
            goto done;
        }

        rn = read(gpmctx->fd, *buffer + pos, *length - pos);
        if (rn == -1) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            ret = errno;
            goto done;
        }
        if (rn == 0) {
            ret = EIO;
            goto done;
        }
        pos += rn;
    }

    ret = 0;

done:
    if (ret) {
        /* on errors we can only close the fd and return */
        gpm_close_socket(gpmctx);
        gpm_epoll_close(gpmctx);
    }
    return ret;
}

/* must be called after the lock has been grabbed */
static uint32_t gpm_next_xid(struct gpm_ctx *gpmctx)
{
    uint32_t xid;

    if (gpmctx->next_xid < 0) {
        gpmctx->next_xid = 1;
        xid = 0;
    } else {
        xid = gpmctx->next_xid++;
    }

    return xid;
}

static struct gpm_ctx *gpm_get_ctx(void)
{
    int ret;

    pthread_once(&gpm_init_once_control, gpm_init_once);

    ret = gpm_grab_sock(&gpm_global_ctx);
    if (ret) {
        return NULL;
    }

    return &gpm_global_ctx;
}

static int gpm_send_recv_loop(struct gpm_ctx *gpmctx, char *send_buffer,
                              uint32_t send_length, char** recv_buffer,
                              uint32_t *recv_length)
{
    int ret;
    int retry_count;

    /* setup timer */
    ret = gpm_timer_setup(gpmctx, RESPONSE_TIMEOUT);
    if (ret)
        return ret;

    for (retry_count = 0; retry_count < MAX_TIMEOUT_RETRY; retry_count++) {
        /* send to proxy */
        ret = gpm_send_buffer(gpmctx, send_buffer, send_length);

        if (ret == 0) {
            /* No error, continue to recv */
        } else if (ret == ETIMEDOUT) {
            /* Close and reopen socket before trying again */
            ret = gpm_retry_socket(gpmctx);
            if (ret != 0)
                return ret;
            ret = ETIMEDOUT;

            /* RETRY entire send */
            continue;
        } else {
            /* Other error */
            return ret;
        }

        /* receive answer */
        ret = gpm_recv_buffer(gpmctx, recv_buffer, recv_length);
        if (ret == 0) {
            /* No error */
            break;
        } else if (ret == ETIMEDOUT) {
            /* Close and reopen socket before trying again */
            ret = gpm_retry_socket(gpmctx);

            /* Free buffer and set it to NULL to prevent free(xdr_reply_ctx) */
            free(*recv_buffer);
            *recv_buffer = NULL;

            if (ret != 0)
                return ret;
            ret = ETIMEDOUT;
        } else {
            /* Other error */
            return ret;
        }
    }

    return ret;
}

OM_uint32 gpm_release_buffer(OM_uint32 *minor_status,
                             gss_buffer_t buffer)
{
    *minor_status = 0;
    if (buffer != GSS_C_NO_BUFFER) {
        if (buffer->value) {
            free(buffer->value);
        }
        buffer->length = 0;
        buffer->value = NULL;
    }
    return GSS_S_COMPLETE;
}

struct gpm_rpc_fn_set {
    xdrproc_t arg_fn;
    xdrproc_t res_fn;
} gpm_xdr_set[] = {
    { /* NULLPROC */
        (xdrproc_t)xdr_void,
        (xdrproc_t)xdr_void,
    },
    { /* GSSX_INDICATE_MECHS */
        (xdrproc_t)xdr_gssx_arg_indicate_mechs,
        (xdrproc_t)xdr_gssx_res_indicate_mechs,
    },
    { /* GSSX_GET_CALL_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_get_call_context,
        (xdrproc_t)xdr_gssx_res_get_call_context,
    },
    { /* GSSX_IMPORT_AND_CANON_NAME */
        (xdrproc_t)xdr_gssx_arg_import_and_canon_name,
        (xdrproc_t)xdr_gssx_res_import_and_canon_name,
    },
    { /* GSSX_EXPORT_CRED */
        (xdrproc_t)xdr_gssx_arg_export_cred,
        (xdrproc_t)xdr_gssx_res_export_cred,
    },
    { /* GSSX_IMPORT_CRED */
        (xdrproc_t)xdr_gssx_arg_import_cred,
        (xdrproc_t)xdr_gssx_res_import_cred,
    },
    { /* GSSX_ACQUIRE_CRED */
        (xdrproc_t)xdr_gssx_arg_acquire_cred,
        (xdrproc_t)xdr_gssx_res_acquire_cred,
    },
    { /* GSSX_STORE_CRED */
        (xdrproc_t)xdr_gssx_arg_store_cred,
        (xdrproc_t)xdr_gssx_res_store_cred,
    },
    { /* GSSX_INIT_SEC_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_init_sec_context,
        (xdrproc_t)xdr_gssx_res_init_sec_context,
    },
    { /* GSSX_ACCEPT_SEC_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_accept_sec_context,
        (xdrproc_t)xdr_gssx_res_accept_sec_context,
    },
    { /* GSSX_RELEASE_HANDLE */
        (xdrproc_t)xdr_gssx_arg_release_handle,
        (xdrproc_t)xdr_gssx_res_release_handle,
    },
    { /* GSSX_GET_MIC */
        (xdrproc_t)xdr_gssx_arg_get_mic,
        (xdrproc_t)xdr_gssx_res_get_mic,
    },
    { /* GSSX_VERIFY */
        (xdrproc_t)xdr_gssx_arg_verify_mic,
        (xdrproc_t)xdr_gssx_res_verify_mic,
    },
    { /* GSSX_WRAP */
        (xdrproc_t)xdr_gssx_arg_wrap,
        (xdrproc_t)xdr_gssx_res_wrap,
    },
    { /* GSSX_UNWRAP */
        (xdrproc_t)xdr_gssx_arg_unwrap,
        (xdrproc_t)xdr_gssx_res_unwrap,
    },
    { /* GSSX_WRAP_SIZE_LIMIT */
        (xdrproc_t)xdr_gssx_arg_wrap_size_limit,
        (xdrproc_t)xdr_gssx_res_wrap_size_limit,
    }
};

int gpm_make_call(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res)
{
    struct gpm_ctx *gpmctx;
    gp_rpc_msg msg;
    XDR xdr_call_ctx = {0};
    XDR xdr_reply_ctx = {0};
    char *send_buffer = NULL;
    char *recv_buffer = NULL;
    uint32_t send_length;
    uint32_t recv_length;
    uint32_t xid;
    bool xdrok;
    bool sockgrab = false;
    int ret;

    send_buffer = malloc(MAX_RPC_SIZE);
    if (send_buffer == NULL)
        return ENOMEM;

    xdrmem_create(&xdr_call_ctx, send_buffer, MAX_RPC_SIZE, XDR_ENCODE);

    memset(&msg, 0, sizeof(gp_rpc_msg));
    msg.header.type = GP_RPC_CALL;
    msg.header.gp_rpc_msg_union_u.chdr.rpcvers = 2;
    msg.header.gp_rpc_msg_union_u.chdr.prog = GSSPROXY;
    msg.header.gp_rpc_msg_union_u.chdr.vers = GSSPROXYVERS;
    msg.header.gp_rpc_msg_union_u.chdr.proc = proc;
    msg.header.gp_rpc_msg_union_u.chdr.cred.flavor = GP_RPC_AUTH_NONE;
    msg.header.gp_rpc_msg_union_u.chdr.cred.body.body_len = 0;
    msg.header.gp_rpc_msg_union_u.chdr.cred.body.body_val = NULL;
    msg.header.gp_rpc_msg_union_u.chdr.verf.flavor = GP_RPC_AUTH_NONE;
    msg.header.gp_rpc_msg_union_u.chdr.verf.body.body_len = 0;
    msg.header.gp_rpc_msg_union_u.chdr.verf.body.body_val = NULL;

    gpmctx = gpm_get_ctx();
    if (!gpmctx) {
        return EINVAL;
    }

    /* grab the lock for the whole conversation */
    ret = gpm_grab_sock(gpmctx);
    if (ret) {
        goto done;
    }
    sockgrab = true;

    msg.xid = xid = gpm_next_xid(gpmctx);

    /* encode header */
    xdrok = xdr_gp_rpc_msg(&xdr_call_ctx, &msg);
    if (!xdrok) {
        ret = EINVAL;
        goto done;
    }

    /* encode data */
    xdrok = gpm_xdr_set[proc].arg_fn(&xdr_call_ctx, (char *)arg);
    if (!xdrok) {
        ret = EINVAL;
        goto done;
    }

    /* set send_length */
    send_length = xdr_getpos(&xdr_call_ctx);

    /* Send request, receive response with timeout */
    ret = gpm_send_recv_loop(gpmctx, send_buffer, send_length, &recv_buffer,
                             &recv_length);
    if (ret)
        goto done;

    /* release the lock */
    gpm_release_sock(gpmctx);
    sockgrab = false;

    /* Create the reply context */
    xdrmem_create(&xdr_reply_ctx, recv_buffer, recv_length, XDR_DECODE);

    /* decode header */
    memset(&msg, 0, sizeof(gp_rpc_msg));
    xdrok = xdr_gp_rpc_msg(&xdr_reply_ctx, &msg);
    if (!xdrok) {
        ret = EINVAL;
        goto done;
    }

    if (msg.xid != xid ||
        msg.header.type != GP_RPC_REPLY ||
        msg.header.gp_rpc_msg_union_u.rhdr.status != GP_RPC_MSG_ACCEPTED ||
        msg.header.gp_rpc_msg_union_u.rhdr.gp_rpc_reply_header_u.accepted.reply_data.status != GP_RPC_SUCCESS) {
        ret = EINVAL;
        goto done;
    }

    /* decode answer */
    xdrok = gpm_xdr_set[proc].res_fn(&xdr_reply_ctx, (char *)res);
    if (!xdrok) {
        ret = EINVAL;
    }

done:
    gpm_timer_close(gpmctx);
    gpm_epoll_close(gpmctx);

    if (sockgrab) {
        gpm_release_sock(gpmctx);
    }
    xdr_free((xdrproc_t)xdr_gp_rpc_msg, (char *)&msg);
    xdr_destroy(&xdr_call_ctx);

    if (recv_buffer != NULL)
        xdr_destroy(&xdr_reply_ctx);

    free(send_buffer);
    free(recv_buffer);

    return ret;
}

void gpm_free_xdrs(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res)
{
    xdr_free(gpm_xdr_set[proc].arg_fn, (char *)arg);
    xdr_free(gpm_xdr_set[proc].res_fn, (char *)res);
}

