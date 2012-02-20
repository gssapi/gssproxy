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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include "gp_proxy.h"

#define CRED_TYPE_NONE 0x00
#define CRED_TYPE_UNIX 0x01
#define CRED_TYPE_SELINUX 0x02

struct gp_creds {
    int type;
    struct ucred ucred;
};

#define FRAGMENT_BIT (1 << 31)

struct unix_sock_conn {

    int sd;

    struct sockaddr_un sock_addr;
    socklen_t sock_addr_len;

};

struct gp_conn {
    struct gssproxy_ctx *gpctx;
    struct unix_sock_conn us;
    struct gp_creds creds;
};

struct gp_buffer {
    struct gp_conn *conn;
    uint8_t *data;
    size_t size;
    size_t pos;
};

void gp_conn_free(struct gp_conn *conn)
{
    if (conn->us.sd != -1) {
        close(conn->us.sd);
    }
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

int init_unix_socket(const char *file_name)
{
    struct sockaddr_un addr = {0};
    mode_t old_mode;
    int ret = 0;
    int fd = -1;

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
        goto done;
    }

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    ret = listen(fd, 10);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    ret = set_status_flags(fd, O_NONBLOCK);
    if (ret != 0) {
        goto done;
    }

    ret = set_fd_flags(fd, FD_CLOEXEC);
    if (ret != 0) {
        goto done;
    }

done:
    if (ret) {
        syslog(LOG_ERR, "Failed to create Unix Socket! (%d:%s)",
               ret, strerror(ret));
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
    }
    umask(old_mode);
    return fd;
}

/* TODO: use getpeercon for SeLinux context */

static int get_peercred(int fd, struct gp_conn *conn)
{
    socklen_t len;
    int ret;

    len = sizeof(struct ucred);
    ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &conn->creds.ucred, &len);
    if (ret == -1) {
        return errno;
    }
    if (len != sizeof(struct ucred)) {
        return EIO;
    }

    conn->creds.type |= CRED_TYPE_UNIX;
    return 0;
}


static void gp_socket_read(verto_ctx *vctx, verto_ev *ev);

static void gp_socket_schedule_read(verto_ctx *vctx, struct gp_buffer *rbuf)
{
    verto_ev *ev;

    ev = verto_add_io(vctx, VERTO_EV_FLAG_IO_READ,
                      gp_socket_read, rbuf->conn->us.sd);
    if (!ev) {
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
    size_t rn;
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
        ret = gp_query_new(rbuf->conn->gpctx->workers, rbuf->conn,
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
        if (wn < sizeof(size)) {
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
    conn->gpctx = verto_get_private(ev);
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
        goto done;
    }

    ret = set_fd_flags(fd, FD_CLOEXEC);
    if (ret) {
        goto done;
    }

    ret = get_peercred(fd, conn);
    if (ret) {
        goto done;
    }

    gp_setup_reader(vctx, conn);

    ret = 0;

done:
    if (ret) {
        syslog(LOG_WARNING, "Error connecting client: (%d:%s)",
                            ret, strerror(ret));
        gp_conn_free(conn);
    }
}

