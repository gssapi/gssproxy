/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi.h>

int gp_get_mic(struct gp_call_ctx *gpcall UNUSED,
               union gp_rpc_arg *arg,
               union gp_rpc_res *res)
{
    gss_buffer_desc message_buffer = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc message_token = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_get_mic *gma;
    struct gssx_res_get_mic *gmr;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;
    int exp_ctx_type;

    gma = &arg->get_mic;
    gmr = &res->get_mic;

    GPRPCDEBUG(gssx_arg_get_mic, gma);

    exp_ctx_type = gp_get_exported_context_type(&gma->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &gma->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    gp_conv_gssx_to_buffer(&gma->message_buffer, &message_buffer);

    ret_maj = gss_get_mic(&ret_min, context_handle,
                          gma->qop_req, &message_buffer, &message_token);
    if (ret_maj) {
        goto done;
    }

    gmr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!gmr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, GSS_C_NO_OID,
                                       &context_handle,
                                       gmr->context_handle);
    if (ret_maj) {
        goto done;
    }

    gmr->qop_state = calloc(1, sizeof(gssx_qop));
    if (!gmr->qop_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    /* what is the point of returning an input parameter ? - gd */
    *gmr->qop_state = gma->qop_req;

    ret = gp_conv_buffer_to_gssx(&message_token, &gmr->token_buffer);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(ret_maj, ret_min,
                                 GSS_C_NO_OID, &gmr->status);
    GPRPCDEBUG(gssx_res_get_mic, gmr);
    gss_release_buffer(&ret_min, &message_token);
    return ret;
}
