/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

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
