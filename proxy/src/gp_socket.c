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
#include "gp_utils.h"

struct unix_sock_conn {

    struct sockaddr_un sock_addr;
    socklen_t sock_addr_len;

#ifdef HAVE_UCRED
    struct ucred creds;
#else
    struct noucred {
        pid_t pid;
        uid_t uid;
        gid_t gid;
    } creds;
#endif
};



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

static int get_peercred(int fd, struct unix_sock_conn *conn)
{
#ifdef HAVE_UCRED
    socklen_t len;
    int ret;

    len = sizeof(struct ucred);
    ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &conn->creds, &len);
    if (ret == -1) {
        return errno;
    }
    if (len != sizeof(struct ucred)) {
        return EIO;
    }
#else
    conn->creds.pid = -1;
    conn->creds.uid = -1;
    conn->creds.gid = -1;
#endif
    return 0;
}

static void free_unix_sock_conn(verto_ctx *vctx, verto_ev *ev)
{
    struct unix_sock_conn *conn;

    conn = verto_get_private(ev);

    free(conn);
}

void client_sock_conn(verto_ctx *vctx, verto_ev *ev)
{
    struct unix_sock_conn *conn;
    int fd;

    fd = verto_get_fd(ev);
    conn = verto_get_private(ev);

    syslog(LOG_ERR, "Ok you got here (pid=%d, uid=%d, gid=%d)!",
           conn->creds.pid, conn->creds.uid, conn->creds.gid);

    verto_del(ev);
    close(fd);
}

void accept_sock_conn(verto_ctx *vctx, verto_ev *ev)
{
    struct unix_sock_conn *conn = NULL;
    verto_ev *nev;
    int vflags;
    int listen_fd;
    int fd = -1;
    int ret;

    conn = malloc(sizeof(struct unix_sock_conn));
    if (!conn) {
        ret = ENOMEM;
        goto done;
    }

    listen_fd = verto_get_fd(ev);
    fd = accept(listen_fd,
                (struct sockaddr *)&conn->sock_addr,
                &conn->sock_addr_len);
    if (fd == -1) {
        ret = errno;
        if (ret == EINTR) {
            /* let the event loop retry later */
            return;
        }
        goto done;
    }

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

    vflags = VERTO_EV_FLAG_PERSIST | VERTO_EV_FLAG_IO_READ;
    nev = verto_add_io(vctx, vflags, client_sock_conn, fd);
    if (!nev) {
        ret = ENOMEM;
        goto done;
    }
    verto_set_private(nev, conn, free_unix_sock_conn);

done:
    if (ret) {
        syslog(LOG_WARNING, "Error connecting client: (%d:%s)",
                            ret, strerror(ret));
        if (fd != -1) {
            close(fd);
        }
        free(conn);
    }
}

