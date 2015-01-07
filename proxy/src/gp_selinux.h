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

#ifndef _GP_SELINUX_H_
#define _GP_SELINUX_H_

#ifdef HAVE_SELINUX

#include <selinux/context.h>
#define SELINUX_CTX context_t
#include <selinux/selinux.h>
#define SEC_CTX security_context_t

#define SELINUX_context_new context_new
#define SELINUX_context_free context_free
#define SELINUX_context_str context_str
#define SELINUX_context_type_get context_type_get
#define SELINUX_context_user_get context_user_get
#define SELINUX_context_role_get context_role_get
#define SELINUX_context_range_get context_range_get
#define SELINUX_getpeercon getpeercon
#define SELINUX_freecon freecon

#else /* not HAVE_SELINUX */

#define SELINUX_CTX void *
#define SEC_CTX void *

#define SELINUX_context_new(x) NULL
#define SELINUX_context_free(x) (x) = NULL
#define SELINUX_context_dummy_get(x) "<SELinux not compiled in>"
#define SELINUX_context_str SELINUX_context_dummy_get
#define SELINUX_context_type_get SELINUX_context_dummy_get
#define SELINUX_context_user_get SELINUX_context_dummy_get
#define SELINUX_context_role_get SELINUX_context_dummy_get
#define SELINUX_context_range_get SELINUX_context_dummy_get

#include <errno.h>
#define SELINUX_getpeercon(x, y) -1; do { \
    *(y) = NULL; \
    errno = ENOTSUP; \
} while(0)

#define SELINUX_freecon(x) (x) = NULL

#endif /* done HAVE_SELINUX */

#endif  /*_GP_SELINUX_H_ */
