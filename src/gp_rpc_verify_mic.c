/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi.h>

int gp_verify_mic(struct gp_call_ctx *gpcall UNUSED,
                  union gp_rpc_arg *arg,
                  union gp_rpc_res *res)
{
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_verify_mic *vma;
    struct gssx_res_verify_mic *vmr;
    gss_buffer_desc message_buffer;
    gss_buffer_desc token_buffer;
    gss_qop_t qop_state;
    int exp_ctx_type;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;

    vma = &arg->verify_mic;
    vmr = &res->verify_mic;

    GPRPCDEBUG(gssx_arg_verify_mic, vma);

    exp_ctx_type = gp_get_exported_context_type(&vma->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &vma->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    gp_conv_gssx_to_buffer(&vma->message_buffer, &message_buffer);
    gp_conv_gssx_to_buffer(&vma->token_buffer, &token_buffer);

    ret_maj = gss_verify_mic(&ret_min, context_handle,
                             &message_buffer, &token_buffer,
                             &qop_state);
    if (ret_maj) {
        goto done;
    }

    vmr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!vmr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, GSS_C_NO_OID,
                                       &context_handle,
                                       vmr->context_handle);
    if (ret_maj) {
        goto done;
    }

    vmr->qop_state = calloc(1, sizeof(gssx_qop));
    if (!vmr->qop_state) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    *vmr->qop_state = qop_state;

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(ret_maj, ret_min,
                                 GSS_C_NO_OID,
                                 &vmr->status);
    GPRPCDEBUG(gssx_res_verify_mic, vmr);
    return ret;
}
