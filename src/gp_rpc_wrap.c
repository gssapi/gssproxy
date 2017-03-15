/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi.h>

int gp_wrap(struct gp_call_ctx *gpcall UNUSED,
            union gp_rpc_arg *arg,
            union gp_rpc_res *res)
{
    gss_buffer_desc input_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_message_buffer = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_wrap *wa;
    struct gssx_res_wrap *wr;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;
    int exp_ctx_type;
    int conf_state = 0;

    wa = &arg->wrap;
    wr = &res->wrap;

    GPRPCDEBUG(gssx_arg_wrap, wa);

    exp_ctx_type = gp_get_exported_context_type(&wa->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &wa->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    /* apparently it is ok to send an empty message, in that case we dont need
     * to bother to do any conversion - gd */
    if ((wa->message_buffer.message_buffer_len > 0) &&
        (wa->message_buffer.message_buffer_val != NULL)) {
        gp_conv_gssx_to_buffer(&wa->message_buffer.message_buffer_val[0],
                               &input_message_buffer);
    }

    ret_maj = gss_wrap(&ret_min,
                       context_handle,
                       wa->conf_req,
                       wa->qop_state,
                       &input_message_buffer,
                       &conf_state,
                       &output_message_buffer);
    if (ret_maj) {
        goto done;
    }

    wr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!wr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, GSS_C_NO_OID,
                                       &context_handle, wr->context_handle);
    if (ret_maj) {
        goto done;
    }

    wr->qop_state = malloc(sizeof(gssx_qop));
    if (!wr->qop_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    *wr->qop_state = wa->qop_state;

    wr->conf_state = malloc(sizeof(bool_t));
    if (!wr->conf_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    *wr->conf_state = conf_state;

    wr->token_buffer.token_buffer_val = calloc(1, sizeof(gssx_buffer));
    if (!wr->token_buffer.token_buffer_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    wr->token_buffer.token_buffer_len = 1;

    ret = gp_conv_buffer_to_gssx(&output_message_buffer,
                                 &wr->token_buffer.token_buffer_val[0]);
    if (ret ) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(ret_maj, ret_min,
                                 GSS_C_NO_OID, &wr->status);
    GPRPCDEBUG(gssx_res_wrap, wr);
    gss_release_buffer(&ret_min, &output_message_buffer);
    return ret;
}
