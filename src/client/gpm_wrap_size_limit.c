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

#include "gssapi_gpm.h"
#include "src/gp_conv.h"

OM_uint32 gpm_wrap_size_limit(OM_uint32 *minor_status,
                              gssx_ctx *context_handle,
                              int conf_req,
                              gss_qop_t qop_req,
                              OM_uint32 size_req,
                              OM_uint32 *max_size)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_wrap_size_limit *arg = &uarg.wrap_size_limit;
    gssx_res_wrap_size_limit *res = &ures.wrap_size_limit;
    uint32_t ret_min = 0;
    uint32_t ret_maj = 0;
    int ret = 0;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    if (!context_handle) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* format request */
    arg->context_handle = *context_handle;
    arg->conf_req = conf_req;
    arg->qop_state = qop_req;
    arg->req_output_size = size_req;

    /* execute proxy request */
    ret = gpm_make_call(GSSX_WRAP_SIZE_LIMIT, &uarg, &ures);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* format reply */
    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_min = res->status.minor_status;
        ret_maj = res->status.major_status;
        goto done;
    }

    if (max_size) {
        *max_size = res->max_input_size;
    }

done:
    /* prevent the context handle from being destroyed in gpm_free_xdrs */
    memset(&arg->context_handle, 0, sizeof(gssx_ctx));

    gpm_free_xdrs(GSSX_WRAP_SIZE_LIMIT, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}
