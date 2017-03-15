/* Copyright (C) 2013 the GSS-PROXY contributors, see COPYING for license */

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
    size_t len = 0;
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
    size_t len = 0;
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

uint32_t gp_add_option(gssx_option **options_val, u_int *options_len,
                       const void *option, size_t option_len,
                       const void *value, size_t value_len)
{
    gssx_option opt = { 0 };
    gssx_option *out;
    uint32_t ret;

    opt.option.octet_string_val = malloc(option_len);
    if (!opt.option.octet_string_val) {
        ret = ENOMEM;
        goto done;
    }
    memcpy(opt.option.octet_string_val, option, option_len);
    opt.option.octet_string_len = option_len;

    if (value_len != 0) {
        opt.value.octet_string_val = malloc(value_len);
        if (!opt.value.octet_string_val) {
            ret = ENOMEM;
            goto done;
        }
        memcpy(opt.value.octet_string_val, value, value_len);
        opt.value.octet_string_len = value_len;
    }

    out = realloc(*options_val, (*options_len + 1) * sizeof(gssx_option));
    if (!out) {
        ret = ENOMEM;
        goto done;
    }

    out[*options_len] = opt;
    *options_val = out;
    (*options_len)++;

    ret = 0;

done:
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_option, (char *)&opt);
    }
    return ret;
}
