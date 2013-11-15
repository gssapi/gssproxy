/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>
   Copyright (C) 2012 Guenther Deschner <guenther.deschner@redhat.com>

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
#include <gssapi/gssapi.h>

int gp_unwrap(struct gp_call_ctx *gpcall,
              union gp_rpc_arg *arg,
              union gp_rpc_res *res)
{
    gss_buffer_desc input_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_unwrap *uwa;
    struct gssx_res_unwrap *uwr;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;
    int exp_ctx_type;
    int conf_state = 0;
    gss_qop_t qop_state = 0;

    uwa = &arg->unwrap;
    uwr = &res->unwrap;

    exp_ctx_type = gp_get_exported_context_type(&uwa->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &uwa->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    /* apparently it is ok to send an empty message, in that case we dont need
     * to bother to do any conversion - gd */
    if ((uwa->token_buffer.token_buffer_len > 0) &&
        (uwa->token_buffer.token_buffer_val != NULL)) {
        gp_conv_gssx_to_buffer(&uwa->token_buffer.token_buffer_val[0],
                               &input_message_buffer);
    }

    ret_maj = gss_unwrap(&ret_min,
                         context_handle,
                         &input_message_buffer,
                         &output_message_buffer,
                         &conf_state,
                         &qop_state);
    if (ret_maj) {
        goto done;
    }

    uwr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!uwr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, GSS_C_NO_OID,
                                       &context_handle,
                                       uwr->context_handle);
    if (ret_maj) {
        goto done;
    }

    uwr->qop_state = malloc(sizeof(gssx_qop));
    if (!uwr->qop_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    *uwr->qop_state = uwa->qop_state;

    uwr->conf_state = malloc(sizeof(bool_t));
    if (!uwr->conf_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    *uwr->conf_state = conf_state;

    uwr->message_buffer.message_buffer_val = calloc(1, sizeof(gssx_buffer));
    if (!uwr->message_buffer.message_buffer_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    uwr->message_buffer.message_buffer_len = 1;

    ret = gp_conv_buffer_to_gssx(&output_message_buffer,
                                 &uwr->message_buffer.message_buffer_val[0]);
    if (ret ) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(&uwa->call_ctx,
                                 ret_maj, ret_min,
                                 GSS_C_NO_OID,
                                 &uwr->status);
    gss_release_buffer(&ret_min, &output_message_buffer);
    return ret;
}
