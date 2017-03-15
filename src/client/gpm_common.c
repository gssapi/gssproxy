/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#define FRAGMENT_BIT (1 << 31)

struct gpm_ctx {
    pthread_mutex_t lock;
    int fd;

    /* these are only meaningful if fd != -1 */
    pid_t pid;
    uid_t uid;
    gid_t gid;

    int next_xid;
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
            ret = 0;
            wn = send(gpmctx->fd, &size, sizeof(uint32_t), MSG_NOSIGNAL);
            if (wn == -1) {
                ret = errno;
            }
        } while (ret == EINTR);
        if (wn != 4) {
            /* reopen and retry once */
            if (retry == false) {
                gpm_close_socket(gpmctx);
                ret = gpm_open_socket(gpmctx);
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
        wn = send(gpmctx->fd, buffer + pos, length - pos, MSG_NOSIGNAL);
        if (wn == -1) {
            if (errno == EINTR) {
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
                           char *buffer, uint32_t *length)
{
    uint32_t size;
    ssize_t rn;
    size_t pos;
    int ret;

    do {
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

    pos = 0;
    while (*length > pos) {
        rn = read(gpmctx->fd, buffer + pos, *length - pos);
        if (rn == -1) {
            if (errno == EINTR) {
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

static void gpm_release_ctx(struct gpm_ctx *gpmctx)
{
    gpm_release_sock(gpmctx);
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
    XDR xdr_call_ctx;
    XDR xdr_reply_ctx;
    char buffer[MAX_RPC_SIZE];
    uint32_t length;
    uint32_t xid;
    bool xdrok;
    bool sockgrab = false;
    int ret;

    xdrmem_create(&xdr_call_ctx, buffer, MAX_RPC_SIZE, XDR_ENCODE);
    xdrmem_create(&xdr_reply_ctx, buffer, MAX_RPC_SIZE, XDR_DECODE);

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

    /* send to proxy */
    ret = gpm_send_buffer(gpmctx, buffer, xdr_getpos(&xdr_call_ctx));
    if (ret) {
        goto done;
    }

    /* receive answer */
    ret = gpm_recv_buffer(gpmctx, buffer, &length);
    if (ret) {
        goto done;
    }

    /* release the lock */
    gpm_release_sock(gpmctx);
    sockgrab = false;

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
    if (sockgrab) {
        gpm_release_sock(gpmctx);
    }
    xdr_free((xdrproc_t)xdr_gp_rpc_msg, (char *)&msg);
    xdr_destroy(&xdr_call_ctx);
    xdr_destroy(&xdr_reply_ctx);
    gpm_release_ctx(gpmctx);
    return ret;
}

void gpm_free_xdrs(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res)
{
    xdr_free(gpm_xdr_set[proc].arg_fn, (char *)arg);
    xdr_free(gpm_xdr_set[proc].res_fn, (char *)res);
}

