/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Simo Sorce <simo.sorce@redhat.com>

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

#include "gssapi_gpm.h"

OM_uint32 gpm_inquire_context(OM_uint32 *minor_status,
                              gssx_ctx *context_handle,
                              gssx_name **src_name,
                              gssx_name **targ_name,
                              OM_uint32 *lifetime_rec,
                              gss_OID *mech_type,
                              OM_uint32 *ctx_flags,
                              int *locally_initiated,
                              int *open)
{
    OM_uint32 ret_maj;
    OM_uint32 tmp_min;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!context_handle) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (src_name) {
        ret_maj = gpm_duplicate_name(minor_status,
                                     &context_handle->src_name,
                                     src_name);
        if (ret_maj != GSS_S_COMPLETE) {
            return ret_maj;
        }
    }

    if (targ_name) {
        ret_maj = gpm_duplicate_name(minor_status,
                                     &context_handle->targ_name,
                                     targ_name);
        if (ret_maj != GSS_S_COMPLETE) {
            if (src_name) {
                (void)gpm_release_name(&tmp_min, src_name);
            }
            return ret_maj;
        }
    }

    if (lifetime_rec) {
        *lifetime_rec = (OM_uint32)context_handle->lifetime;
    }

    if (mech_type) {
        ret = gp_conv_gssx_to_oid_alloc(&context_handle->mech, mech_type);
        if (ret) {
            if (src_name) {
                (void)gpm_release_name(&tmp_min, src_name);
            }
            if (targ_name) {
                (void)gpm_release_name(&tmp_min, targ_name);
            }
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
    }

    if (ctx_flags) {
        *ctx_flags = (OM_uint32)context_handle->ctx_flags;
    }

    if (locally_initiated) {
        if (context_handle->locally_initiated) {
            *locally_initiated = 1;
        } else {
            *locally_initiated = 0;
        }
    }

    if (open) {
        if (context_handle->open) {
            *open = 1;
        } else {
            *open = 0;
        }
    }

    return GSS_S_COMPLETE;
}
