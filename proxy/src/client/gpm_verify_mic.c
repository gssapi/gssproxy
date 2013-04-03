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

OM_uint32 gpm_verify_mic(OM_uint32 *minor_status,
                         gssx_ctx *context_handle,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token,
                         gss_qop_t *qop_state)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_verify_mic *arg = &uarg.verify_mic;
    gssx_res_verify_mic *res = &ures.verify_mic;
    uint32_t ret_min = 0;
    uint32_t ret_maj = 0;
    int ret = 0;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    if (!context_handle) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* format request */
    /* NOTE: the final free will also release the old context */
    arg->context_handle = *context_handle;
    ret = gp_conv_buffer_to_gssx(message_buffer, &arg->message_buffer);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(message_token, &arg->token_buffer);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* execute proxy request */
    ret = gpm_make_call(GSSX_VERIFY, &uarg, &ures);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* Check and save error status */
    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_min = res->status.minor_status;
        ret_maj = res->status.major_status;
        goto done;
    }

    if (qop_state) {
        *qop_state = *res->qop_state;
    }

done:
    /* Steal the new context if available.
     * NOTE: We do not want it to be freed by xdr_free, so copy the contents
     * and cear up the structure to be freed so contents are not freed. */
    if (res->context_handle) {
        *context_handle = *res->context_handle;
        memset(res->context_handle, 0, sizeof(gssx_ctx));
    } else {
        /* prevent the contexthandle from being destroyed in case of server
         * error. */
        memset(&arg->context_handle, 0, sizeof(gssx_ctx));
    }

    gpm_free_xdrs(GSSX_VERIFY, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}
