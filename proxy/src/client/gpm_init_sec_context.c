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

#include "gssapi_gpm.h"
#include "src/gp_conv.h"

OM_uint32 gpm_init_sec_context(OM_uint32 *minor_status,
                               gssx_cred *cred_handle,
                               gssx_ctx **context_handle,
                               gssx_name *target_name,
                               gss_OID mech_type,
                               OM_uint32 req_flags,
                               OM_uint32 time_req,
                               gss_channel_bindings_t input_cb,
                               gss_buffer_t input_token,
                               gss_OID *actual_mech_type,
                               gss_buffer_t output_token,
                               OM_uint32 *ret_flags,
                               OM_uint32 *time_rec)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_init_sec_context *arg = &uarg.init_sec_context;
    gssx_res_init_sec_context *res = &ures.init_sec_context;
    gssx_ctx *ctx = NULL;
    gss_OID_desc *mech = NULL;
    gss_buffer_t outbuf = NULL;
    uint32_t ret_maj = GSS_S_COMPLETE;
    uint32_t ret_min = 0;
    int ret;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    /* prepare proxy request */
    if (cred_handle != NULL) {
        arg->cred_handle = cred_handle;
    }

    if (*context_handle) {
        arg->context_handle = *context_handle;
    }

    arg->target_name = target_name;

    ret = gp_conv_oid_to_gssx(mech_type, &arg->mech_type);
    if (ret) {
        goto done;
    }

    arg->req_flags = req_flags;
    arg->time_req = time_req;

    if (input_cb) {
        ret = gp_conv_cb_to_gssx_alloc(input_cb, &arg->input_cb);
        if (ret) {
            goto done;
        }
    }

    if (input_token != GSS_C_NO_BUFFER) {
        ret = gp_conv_buffer_to_gssx_alloc(input_token, &arg->input_token);
        if (ret) {
            goto done;
        }
    }

    /* execute proxy request */
    ret = gpm_make_call(GSSX_INIT_SEC_CONTEXT, &uarg, &ures);
    if (ret) {
        gpm_save_internal_status(ret, gp_strerror(ret));
        goto done;
    }

    /* return values */
    if (actual_mech_type) {
        if (res->status.mech.octet_string_len) {
            ret = gp_conv_gssx_to_oid_alloc(&res->status.mech, &mech);
            if (ret) {
                goto done;
            }
        }
    }

    if (res->context_handle) {
        ctx = res->context_handle;
        /* we are stealing the delegated creds on success, so we do not want
        * it to be freed by xdr_free */
        res->context_handle = NULL;
    }

    if (res->output_token) {
        ret = gp_conv_gssx_to_buffer_alloc(res->output_token, &outbuf);
        if (ret) {
            gpm_save_internal_status(ret, gp_strerror(ret));
            goto done;
        }
    }

    ret_maj = res->status.major_status;
    ret_min = res->status.minor_status;
    gpm_save_status(&res->status);

done:
    if (ret != 0) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
    }

    /* we are putting our copy of these structures in here,
     * and do not want it to be freed by xdr_free */
    arg->context_handle = NULL;
    arg->cred_handle = NULL;
    arg->target_name = NULL;
    gpm_free_xdrs(GSSX_INIT_SEC_CONTEXT, &uarg, &ures);

    if (ret_maj == GSS_S_COMPLETE || ret_maj == GSS_S_CONTINUE_NEEDED) {
        if (actual_mech_type) {
            *actual_mech_type = mech;
        }
        if (outbuf) {
            *output_token = *outbuf;
            free(outbuf);
        }
        if (ret_flags) {
            *ret_flags = ctx->ctx_flags;
        }
        if (time_rec) {
            *time_rec = ctx->lifetime;
        }
    } else {
        if (ctx) {
            xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)ctx);
            free(ctx);
            ctx = NULL;
        }
        if (mech) {
            free(mech->elements);
            free(mech);
        }
        if (outbuf) {
            free(outbuf->value);
            free(outbuf);
        }
    }

    /* always replace old ctx handle and set new */
    if (*context_handle) {
        xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)*context_handle);
        free(*context_handle);
    }
    *context_handle = ctx;

    *minor_status = ret_min;
    return ret_maj;
}
