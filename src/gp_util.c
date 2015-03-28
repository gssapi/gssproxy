/*
   GSS-PROXY

   Copyright (C) 2013 Red Hat, Inc.
   Copyright (C) 2013 Simo Sorce <simo.sorce@redhat.com>

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
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "gp_common.h"

bool gp_same(const char *a, const char *b)
{
    if ((a == b) || strcmp(a, b) == 0) {
        return true;
    }

    return false;
}

bool gp_boolean_is_true(const char *s)
{
    if (strcasecmp(s, "1") == 0 ||
        strcasecmp(s, "on") == 0 ||
        strcasecmp(s, "true") == 0 ||
        strcasecmp(s, "yes") == 0) {
        return true;
    }

    return false;
}

char *gp_getenv(const char *name)
{
#if HAVE_SECURE_GETENV
    return secure_getenv(name);
#elif HAVE___SECURE_GETENV
    return __secure_getenv(name);
#else
#include <unistd.h>
#include <sys/types.h>
#warning secure_getenv not available, falling back to poorman emulation
    if ((getuid() == geteuid()) &&
        (getgid() == getegid())) {
        return getenv(name);
    }
    return NULL;
#endif
}

/* NOTE: because strerror_r() is such a mess with glibc, we need to do some
 * magic checking to find out what function prototype is being used of the
 * two incompatible ones, and pray it doesn't change in the future.
 * On top of that to avoid impacting the current code too much we've got to use
 * thread-local storage to hold a buffer.
 * gp_strerror() is basically a thread-safe version of strerror() that can
 * never fail.
 */
const char gp_internal_err[] = "Internal strerror_r() error.";
#define MAX_GP_STRERROR 1024
char *gp_strerror(int errnum)
{
    static __thread char buf[MAX_GP_STRERROR];
    int saved_errno = errno;

#if ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE)
    /* XSI version */
    int ret;

    ret = strerror_r(errnum, buf, MAX_GP_STRERROR);
    if (ret == -1) ret = errno;
    switch (ret) {
    case 0:
        break;
    case EINVAL:
        ret = snprintf(buf, MAX_GP_STRERROR,
                       "Unknown error code: %d", errnum);
        if (ret > 0) break;
        /* fallthrough */
    default:
        ret = snprintf(buf, MAX_GP_STRERROR,
                       "Internal error describing error code: %d", errnum);
        if (ret > 0) break;
        memset(buf, 0, MAX_GP_STRERROR);
        strncpy(buf, gp_internal_err, MAX_GP_STRERROR);
        buf[MAX_GP_STRERROR -1] = '\0';
    }
#else
    /* GNU-specific version */
    char *ret;

    ret = strerror_r(errnum, buf, MAX_GP_STRERROR);
    if (ret == NULL) {
        memset(buf, 0, MAX_GP_STRERROR);
        strncpy(buf, gp_internal_err, MAX_GP_STRERROR);
        buf[MAX_GP_STRERROR -1] = '\0';
    } else if (ret != buf) {
        memset(buf, 0, MAX_GP_STRERROR);
        strncpy(buf, ret, MAX_GP_STRERROR);
        buf[MAX_GP_STRERROR -1] = '\0';
    }
#endif

    errno = saved_errno;
    return buf;
}

ssize_t gp_safe_read(int fd, void *buf, size_t count)
{
    char *b = (char *)buf;
    ssize_t len = 0;
    ssize_t ret;

    do {
        ret = read(fd, &b[len], count - len);
        if (ret == -1) {
            if (errno == EINTR) continue;
            return ret;
        }
        if (ret == 0) break; /* EOF */
        len += ret;
    } while (count > len);

    return len;
}

ssize_t gp_safe_write(int fd, const void *buf, size_t count)
{
    const char *b = (const char *)buf;
    ssize_t len = 0;
    ssize_t ret;

    do {
        ret = write(fd, &b[len], count - len);
        if (ret == -1) {
            if (errno == EINTR) continue;
            return ret;
        }
        if (ret == 0) break; /* EOF */
        len += ret;
    } while (count > len);

    return len;
}
