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

int gp_wrap_size_limit(struct gp_call_ctx *gpcall,
                       union gp_rpc_arg *arg,
                       union gp_rpc_res *res)
{
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_wrap_size_limit *wsla;
    struct gssx_res_wrap_size_limit *wslr;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;
    int exp_ctx_type;
    OM_uint32 max_size;

    wsla = &arg->wrap_size_limit;
    wslr = &res->wrap_size_limit;

    exp_ctx_type = gp_get_exported_context_type(&wsla->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &wsla->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    ret_maj = gss_wrap_size_limit(&ret_min,
                                  context_handle,
                                  wsla->conf_req,
                                  wsla->qop_state,
                                  wsla->req_output_size,
                                  &max_size);
    if (ret_maj) {
        goto done;
    }

    wslr->max_input_size = max_size;

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(&wsla->call_ctx,
                                 ret_maj, ret_min,
                                 GSS_C_NO_OID,
                                 &wslr->status);
    return ret;
}
