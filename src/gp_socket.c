/* Copyright (C) 2011,2015 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"

#include "gp_proxy.h"
#include "gp_creds.h"
#include "gp_selinux.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define FRAGMENT_BIT (1 << 31)

struct unix_sock_conn {

    int sd;

    struct sockaddr_un sock_addr;
    socklen_t sock_addr_len;

};

struct gp_conn {
    struct gp_sock_ctx *sock_ctx;
    struct unix_sock_conn us;
    struct gp_creds creds;
    SELINUX_CTX selinux_ctx;
    char *program;
};

struct gp_buffer {
    struct gp_conn *conn;
    uint8_t *data;
    size_t size;
    size_t pos;
};

bool gp_selinux_ctx_equal(SELINUX_CTX ctx1, SELINUX_CTX ctx2)
{
    const char *ra, *rb;

    if (ctx1 == ctx2) {
        return true;
    }
    if (ctx1 == NULL || ctx2 == NULL) {
        return false;
    }

    if (strcmp(SELINUX_context_user_get(ctx1),
               SELINUX_context_user_get(ctx2)) != 0) {
        return false;
    }
    if (strcmp(SELINUX_context_role_get(ctx1),
               SELINUX_context_role_get(ctx2)) != 0) {
        return false;
    }
    if (strcmp(SELINUX_context_type_get(ctx1),
               SELINUX_context_type_get(ctx2)) != 0) {
        return false;
    }
    ra = SELINUX_context_range_get(ctx1);
    rb = SELINUX_context_range_get(ctx2);
    if (ra && rb && (strcmp(ra, rb) != 0)) {
        return false;
    }

    return true;
}

bool gp_conn_check_selinux(struct gp_conn *conn, SELINUX_CTX ctx)
{
    if (ctx == NULL) {
        return true;
    }

    if (!(conn->creds.type & CRED_TYPE_SELINUX) ||
         (conn->selinux_ctx == NULL)) {
        return false;
    }

    return gp_selinux_ctx_equal(ctx, conn->selinux_ctx);
}

struct gp_creds *gp_conn_get_creds(struct gp_conn *conn)
{
    return &conn->creds;
}

uid_t gp_conn_get_uid(struct gp_conn *conn)
{
    return conn->creds.ucred.uid;
}

const char *gp_conn_get_socket(struct gp_conn *conn)
{
    return conn->sock_ctx->socket;
}

int gp_conn_get_cid(struct gp_conn *conn)
{
    return conn->us.sd;
}

const char *gp_conn_get_program(struct gp_conn *conn)
{
    return conn->program;
}

void gp_conn_free(struct gp_conn *conn)
{
    if (!conn) return;

    if (conn->us.sd != -1) {
        close(conn->us.sd);
    }
    free(conn->program);
    SELINUX_context_free(conn->selinux_ctx);
    free(conn);
}

static void gp_buffer_free(struct gp_buffer *wbuf)
{
    free(wbuf->data);
    free(wbuf);
}


static int set_status_flags(int fd, int flags)
{
    int cur;
    int ret;

    cur = fcntl(fd, F_GETFL, 0);
    cur |= flags;
    ret = fcntl(fd, F_SETFL, cur);
    if (ret == -1) {
        return errno;
    }
    return 0;
}

static int set_fd_flags(int fd, int flags)
{
    int cur;
    int ret;

    cur = fcntl(fd, F_GETFD, 0);
    cur |= flags;
    ret = fcntl(fd, F_SETFD, cur);
    if (ret == -1) {
        return errno;
    }
    return 0;
}

void free_unix_socket(verto_ctx *ctx UNUSED, verto_ev *ev)
{
    struct gp_sock_ctx *sock_ctx = NULL;
    sock_ctx = verto_get_private(ev);
    free(sock_ctx);
}

struct gp_sock_ctx *init_unix_socket(struct gssproxy_ctx *gpctx,
                                     const char *file_name)
{
    struct sockaddr_un addr = {0};
    struct gp_sock_ctx *sock_ctx;
    mode_t old_mode;
    int ret = 0;
    int fd = -1;

    sock_ctx = calloc(1, sizeof(struct gp_sock_ctx));
    if (!sock_ctx) {
        return NULL;
    }

    /* can't bind if an old socket is around */
    unlink(file_name);

    /* socket should be r/w by anyone */
    old_mode = umask(0111);

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, file_name, sizeof(addr.sun_path)-1);
    addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        ret = errno;
        GPDEBUG("Failed to init socket! (%d: %s)\n", ret, gp_strerror(ret));
        goto done;
    }

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to bind socket %s! (%d: %s)\n", addr.sun_path,
            ret, gp_strerror(ret));
        goto done;
    }

    ret = listen(fd, 10);
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to listen! (%d: %s)\n", ret, gp_strerror(ret));
        goto done;
    }

    ret = set_status_flags(fd, O_NONBLOCK);
    if (ret != 0) {
        GPDEBUG("Failed to set O_NONBLOCK on %d!\n", fd);
        goto done;
    }

    ret = set_fd_flags(fd, FD_CLOEXEC);
    if (ret != 0) {
        GPDEBUG("Failed to set FD_CLOEXEC on %d!\n", fd);
        goto done;
    }

done:
    if (ret) {
        GPERROR("Failed to create Unix Socket! (%d:%s)",
                ret, gp_strerror(ret));
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
        safefree(sock_ctx);
    } else {
        sock_ctx->gpctx = gpctx;
        sock_ctx->socket = file_name;
        sock_ctx->fd = fd;
    }
    umask(old_mode);

    return sock_ctx;
}

static int get_peercred(int fd, struct gp_conn *conn)
{
    SEC_CTX secctx;
    socklen_t len;
    int ret;

    len = sizeof(struct ucred);
    ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &conn->creds.ucred, &len);
    if (ret == -1) {
        ret = errno;
        GPDEBUG("Failed to get SO_PEERCRED options! (%d:%s)\n",
                ret, gp_strerror(ret));
        return ret;
    }
    if (len != sizeof(struct ucred)) {
        return EIO;
    }

    conn->creds.type |= CRED_TYPE_UNIX;

    ret = SELINUX_getpeercon(fd, &secctx);
    if (ret == 0) {
        conn->creds.type |= CRED_TYPE_SELINUX;
        conn->selinux_ctx = SELINUX_context_new(secctx);
        SELINUX_freecon(secctx);
    } else {
        ret = errno;
        GPDEBUG("Failed to get peer's SELinux context (%d:%s)\n",
                ret, gp_strerror(ret));
        /* consider thisnot fatal, selinux may be disabled */
    }

    return 0;
}

static char *get_program(pid_t pid)
{
    char procfile[21];
    char *program;
    int ret, e;
    struct stat sb;

    ret = snprintf(procfile, 20, "/proc/%u/exe", pid);
    if (ret < 0) {
        e = errno;
        GPERROR("Internal error in snprintf: %d (%s)", e, strerror(e));
        return NULL;
    }
    procfile[ret] = '\0';

    program = realpath(procfile, NULL);
    if (program) {
        return program;
    }

    e = errno;
    if (e != ENOENT) {
        GPERROR("Unexpected failure in realpath: %d (%s)", e, strerror(e));
        return NULL;
    }

    /* check if /proc is even around */
    procfile[ret - 4] = '\0';
    ret = stat(procfile, &sb); /* complains if we give it NULL */
    e = errno;
    if (ret == -1 && e == ENOENT) {
        /* kernel thread */
        return NULL;
    }

    GPERROR("Problem with /proc; program name matching won't work: %d (%s)",
            e, strerror(e));
    return NULL;
}

static void gp_socket_read(verto_ctx *vctx, verto_ev *ev);

static void gp_socket_schedule_read(verto_ctx *vctx, struct gp_buffer *rbuf)
{
    verto_ev *ev;

    ev = verto_add_io(vctx, VERTO_EV_FLAG_IO_READ,
                      gp_socket_read, rbuf->conn->us.sd);
    if (!ev) {
        GPDEBUG("Failed to add io/read event!\n");
        gp_conn_free(rbuf->conn);
        gp_buffer_free(rbuf);
        return;
    }
    verto_set_private(ev, rbuf, NULL);
}

static void gp_setup_reader(verto_ctx *vctx, struct gp_conn *conn)
{
    struct gp_buffer *buf;

    /* create initial read buffer */
    buf = calloc(1, sizeof(struct gp_buffer));
    if (!buf) {
        gp_conn_free(conn);
        return;
    }
    buf->conn = conn;

    gp_socket_schedule_read(vctx, buf);
}

static void gp_socket_read(verto_ctx *vctx, verto_ev *ev)
{
    struct gp_buffer *rbuf;
    uint32_t size;
    bool header = false;
    ssize_t rn;
    int ret;
    int fd;

    fd = verto_get_fd(ev);
    rbuf = verto_get_private(ev);

    if (rbuf->data == NULL) {
        header = true;
        /* new connection, need to read length first */
        rn = read(fd, &size, sizeof(uint32_t));
        if (rn == -1) {
            if (errno == EAGAIN || errno == EINTR) {
                /* spin again */
                ret = EAGAIN;
            } else {
                ret = EIO;
            }
            goto done;
        }
        if (rn != sizeof(uint32_t)) {
            /* client closed,
             * or we didn't get even 4 bytes,
             * close conn, not worth trying 1 byte reads at this time */
            ret = EIO;
            goto done;
        }

        /* allocate buffer for receiving data */
        rbuf->size = ntohl(size);

        /* FIXME: need to support multiple fragments */
        /* for now just make sure we have the last fragment bit
         * then remove it */
        if (rbuf->size & FRAGMENT_BIT) {
            rbuf->size &= ~FRAGMENT_BIT;
        } else {
            ret = EIO;
            goto done;
        }

        if (rbuf->size > MAX_RPC_SIZE) {
            /* req too big close conn. */
            ret = EIO;
            goto done;
        }

        rbuf->data = malloc(rbuf->size);
        if (!rbuf->data) {
            ret = ENOMEM;
            goto done;
        }
    }

    errno = 0;
    rn = read(fd, rbuf->data + rbuf->pos, rbuf->size - rbuf->pos);
    if (rn == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* spin again */
            ret = EAGAIN;
        } else {
            ret = EIO;
        }
        goto done;
    }

    if (rn == 0) {
        if (!header) {
            /* client closed before the buffer was fully read */
            ret = EIO;
        } else {
            ret = EAGAIN;
        }
        goto done;
    }

    rbuf->pos += rn;

    if (rbuf->pos == rbuf->size) {
        /* got all data, hand over packet */
        ret = gp_query_new(rbuf->conn->sock_ctx->gpctx->workers, rbuf->conn,
                           rbuf->data, rbuf->size);
        if (ret != 0) {
            /* internal error, not much we can do */
            goto done;
        }

        /* we successfully handed over the data */
        rbuf->data = NULL;
        gp_buffer_free(rbuf);
        return;
    }

    ret = EAGAIN;

done:
    switch (ret) {
    case EAGAIN:
        gp_socket_schedule_read(vctx, rbuf);
        return;
    default:
        gp_conn_free(rbuf->conn);
        gp_buffer_free(rbuf);
    }
}

static void gp_socket_write(verto_ctx *vctx, verto_ev *ev);

static void gp_socket_schedule_write(verto_ctx *vctx, struct gp_buffer *wbuf)
{
    verto_ev *ev;

    ev = verto_add_io(vctx, VERTO_EV_FLAG_IO_WRITE,
                      gp_socket_write, wbuf->conn->us.sd);
    if (!ev) {
        GPDEBUG("Failed to add io/write event!\n");
        gp_conn_free(wbuf->conn);
        gp_buffer_free(wbuf);
        return;
    }
    verto_set_private(ev, wbuf, NULL);
}

void gp_socket_send_data(verto_ctx *vctx, struct gp_conn *conn,
                         uint8_t *buffer, size_t buflen)
{
    struct gp_buffer *wbuf;

    wbuf = calloc(1, sizeof(struct gp_buffer));
    if (!wbuf) {
        /* too bad, must kill the client connection now */
        gp_conn_free(conn);
        return;
    }

    wbuf->conn = conn;
    wbuf->data = buffer;
    wbuf->size = buflen;

    gp_socket_schedule_write(vctx, wbuf);
}

static void gp_socket_write(verto_ctx *vctx, verto_ev *ev)
{
    struct gp_buffer *wbuf;
    struct iovec iov[2];
    uint32_t size;
    ssize_t wn;
    int vecs;
    int fd;

    fd = verto_get_fd(ev);
    wbuf = verto_get_private(ev);

    vecs = 0;

    if (wbuf->pos == 0) {
        /* first write, send the buffer size as packet header */
        size = wbuf->size | FRAGMENT_BIT;
        size = htonl(size);

        iov[0].iov_base = &size;
        iov[0].iov_len = sizeof(size);
        vecs = 1;
    }

    iov[vecs].iov_base = wbuf->data + wbuf->pos;
    iov[vecs].iov_len = wbuf->size - wbuf->pos;
    vecs++;

    errno = 0;
    wn = writev(fd, iov, vecs);
    if (wn == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* try again later */
            gp_socket_schedule_write(vctx, wbuf);
        } else {
            /* error on socket, close and release it */
            gp_conn_free(wbuf->conn);
            gp_buffer_free(wbuf);
        }
        return;
    }
    if (vecs == 2) {
        if (wn < (ssize_t) sizeof(size)) {
            /* don't bother trying to handle sockets that can't
             * buffer even 4 bytes */
            gp_conn_free(wbuf->conn);
            gp_buffer_free(wbuf);
            return;
        }
        wn -= sizeof(size);
    }

    wbuf->pos += wn;
    if (wbuf->size > wbuf->pos) {
        /* short write, reschedule */
        gp_socket_schedule_write(vctx, wbuf);
    } else {
        /* now setup again the reader */
        gp_setup_reader(vctx, wbuf->conn);
        /* all done, free write context */
        gp_buffer_free(wbuf);
    }
}

void accept_sock_conn(verto_ctx *vctx, verto_ev *ev)
{
    struct gp_conn *conn = NULL;
    int listen_fd;
    int fd = -1;
    int ret;

    conn = calloc(1, sizeof(struct gp_conn));
    if (!conn) {
        ret = ENOMEM;
        goto done;
    }
    conn->sock_ctx = verto_get_private(ev);
    conn->us.sd = -1;

    listen_fd = verto_get_fd(ev);
    fd = accept(listen_fd,
                (struct sockaddr *)&conn->us.sock_addr,
                &conn->us.sock_addr_len);
    if (fd == -1) {
        ret = errno;
        if (ret == EINTR) {
            /* let the event loop retry later */
            return;
        }
        goto done;
    }
    conn->us.sd = fd;

    ret = set_status_flags(fd, O_NONBLOCK);
    if (ret) {
        GPDEBUG("Failed to set O_NONBLOCK on %d!\n", fd);
        goto done;
    }

    ret = set_fd_flags(fd, FD_CLOEXEC);
    if (ret) {
        GPDEBUG("Failed to set FD_CLOEXEC on %d!\n", fd);
        goto done;
    }

    ret = get_peercred(fd, conn);
    if (ret) {
        goto done;
    }

    conn->program = get_program(conn->creds.ucred.pid);

    GPDEBUG("Client ");
    if (conn->program) {
        GPDEBUG("(%s) ", conn->program);
    }
    GPDEBUG(" connected (fd = %d)", fd);

    if (conn->creds.type & CRED_TYPE_UNIX) {
        GPDEBUG(" (pid = %d) (uid = %d) (gid = %d)",
                conn->creds.ucred.pid,
                conn->creds.ucred.uid,
                conn->creds.ucred.gid);
    }
    if (conn->creds.type & CRED_TYPE_SELINUX) {
        GPDEBUG(" (context = %s)",
                SELINUX_context_str(conn->selinux_ctx));
    }
    GPDEBUG("\n");

    gp_setup_reader(vctx, conn);

    ret = 0;

done:
    if (ret) {
        GPERROR("Error connecting client: (%d:%s)",
                ret, gp_strerror(ret));
        gp_conn_free(conn);
    }
}

