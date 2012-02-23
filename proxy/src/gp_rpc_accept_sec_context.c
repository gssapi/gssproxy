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

#include "gp_rpc_process.h"

int gp_accept_sec_context(struct gssproxy_ctx *gpctx,
                          union gp_rpc_arg *arg,
                          union gp_rpc_res *res)
{
    struct gssx_arg_accept_sec_context *asca;
    struct gssx_res_accept_sec_context *ascr;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t ach = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc ibuf;
    struct gss_channel_bindings_struct cbs;
    gss_channel_bindings_t pcbs;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_OID oid = GSS_C_NO_OID;
    gss_buffer_desc obuf = GSS_C_EMPTY_BUFFER;
    uint32_t ret_flags;
    gss_cred_id_t dch = GSS_C_NO_CREDENTIAL;
    int ret;

    asca = &arg->accept_sec_context;
    ascr = &res->accept_sec_context;

    if (asca->cred_handle) {
        ret = gp_find_cred(asca->cred_handle, &ach);
        if (ret) {
            ret_maj = GSS_S_NO_CRED;
            ret_min = ret;
            goto done;
        }
    }

    gp_conv_gssx_to_buffer(&asca->input_token, &ibuf);

    if (asca->input_cb) {
        pcbs = &cbs;
        gp_conv_gssx_to_cb(asca->input_cb, pcbs);
    } else {
        pcbs = GSS_C_NO_CHANNEL_BINDINGS;
    }

    ret_maj = gss_accept_sec_context(&ret_min,
                                     &ctx,
                                     ach,
                                     &ibuf,
                                     pcbs,
                                     &src_name,
                                     &oid,
                                     &obuf,
                                     &ret_flags,
                                     NULL,
                                     &dch);
    if (ret_maj) {
        goto done;
    }

    ascr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!ascr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret = gp_conv_ctx_id_to_gssx(&ctx, ascr->context_handle);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ascr->output_token = calloc(1, sizeof(gssx_buffer));
    if (!ascr->output_token) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&obuf, ascr->output_token);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    if (ret_flags & GSS_C_DELEG_FLAG) {
        ascr->delegated_cred_handle = calloc(1, sizeof(gssx_cred));
        if (!ascr->delegated_cred_handle) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ENOMEM;
            goto done;
        }
        ret_maj = gp_export_gssx_cred(&ret_min,
                                      &dch, ascr->delegated_cred_handle);
        if (ret_maj) {
            goto done;
        }
    }

done:
    ret = gp_conv_status_to_gssx(&asca->call_ctx,
                                 ret_maj, ret_min, oid,
                                 &ascr->status);

    if (ret_maj) {
        if (ascr->context_handle) {
            xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)ascr->context_handle);
            free(ascr->context_handle);
        }
        if (ascr->output_token) {
            xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)ascr->output_token);
            free(ascr->output_token);
        }
    }
    gss_release_name(&ret_min, &src_name);
    gss_release_buffer(&ret_min, &obuf);
    gss_release_cred(&ret_min, &dch);
    gss_delete_sec_context(&ret_min, &ctx, GSS_C_NO_BUFFER);

    return ret;
}
