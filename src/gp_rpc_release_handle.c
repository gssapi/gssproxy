/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"

int gp_release_handle(struct gp_call_ctx *gpcall UNUSED,
                      union gp_rpc_arg *arg,
                      union gp_rpc_res *res)
{
    struct gssx_arg_release_handle *rha;
    struct gssx_res_release_handle *rhr;
    uint32_t ret_maj = GSS_S_COMPLETE;
    uint32_t ret_min = 0;
    int ret;

    rha = &arg->release_handle;
    rhr = &res->release_handle;

    GPRPCDEBUG(gssx_arg_release_handle, rha);

    switch (rha->cred_handle.handle_type) {
    case GSSX_C_HANDLE_SEC_CTX:
        /* We do not need release for any security
         * context for now */
        ret_maj = GSS_S_UNAVAILABLE;
        ret_min = 0;
        break;
    case GSSX_C_HANDLE_CRED:
        /* We do not need release for any creds now */
        ret_maj = GSS_S_UNAVAILABLE;
        ret_min = 0;
        break;
    default:
        ret_maj = GSS_S_CALL_BAD_STRUCTURE;
        ret_min = 0;
        break;
    }

    ret = gp_conv_status_to_gssx(ret_maj, ret_min, GSS_C_NO_OID,
                                 &rhr->status);
    GPRPCDEBUG(gssx_res_release_handle, rhr);

    return ret;
}
