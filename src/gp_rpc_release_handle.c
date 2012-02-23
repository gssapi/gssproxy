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

int gp_release_handle(struct gssproxy_ctx *gpctx,
                      struct gp_service *gpsvc,
                      union gp_rpc_arg *arg,
                      union gp_rpc_res *res)
{
    struct gssx_arg_release_handle *rha;
    struct gssx_res_release_handle *rhr;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_cred_id_t cred;
    int ret;

    rha = &arg->release_handle;
    rhr = &res->release_handle;

    switch (rha->cred_handle.handle_type) {
    case GSSX_C_HANDLE_SEC_CTX:
        /* We do not need release for any security
         * context for now */
        ret_maj = GSS_S_UNAVAILABLE;
        ret_min = 0;
        break;
    case GSSX_C_HANDLE_CRED:
        ret = gp_find_cred(&rha->cred_handle.gssx_handle_u.cred_info, &cred);
        if (ret) {
            ret_maj = GSS_S_UNAVAILABLE;
            ret_min = 0;
        } else {
            ret_maj = gss_release_cred(&ret_min, &cred);
        }
        break;
    default:
        ret_maj = GSS_S_CALL_BAD_STRUCTURE;
        ret_min = 0;
        break;
    }

    ret = gp_conv_status_to_gssx(&rha->call_ctx,
                                 ret_maj, ret_min, GSS_C_NO_OID,
                                 &rhr->status);

    return ret;
}
