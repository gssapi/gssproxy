/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"
#include "src/gp_conv.h"

OM_uint32 gpm_get_mic(OM_uint32 *minor_status,
                      gssx_ctx *context_handle,
                      gss_qop_t qop_req,
                      gss_buffer_t message_buffer,
                      gss_buffer_t message_token)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_get_mic *arg = &uarg.get_mic;
    gssx_res_get_mic *res = &ures.get_mic;
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
    arg->qop_req = qop_req;
    ret = gp_conv_buffer_to_gssx(message_buffer, &arg->message_buffer);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* execute proxy request */
    ret = gpm_make_call(GSSX_GET_MIC, &uarg, &ures);
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

    ret = gp_copy_gssx_to_buffer(&res->token_buffer, message_token);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
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

    gpm_free_xdrs(GSSX_GET_MIC, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}
