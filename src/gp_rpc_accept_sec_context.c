/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"

int gp_accept_sec_context(struct gp_call_ctx *gpcall,
                          union gp_rpc_arg *arg,
                          union gp_rpc_res *res)
{
    struct gssx_arg_accept_sec_context *asca;
    struct gssx_res_accept_sec_context *ascr;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t ach = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc ibuf;
    struct gss_channel_bindings_struct cbs;
    gss_channel_bindings_t pcbs;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_OID oid = GSS_C_NO_OID;
    gss_buffer_desc obuf = GSS_C_EMPTY_BUFFER;
    uint32_t ret_flags;
    gss_cred_id_t dch = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t *pdch = NULL;
    int exp_ctx_type;
    int exp_creds_type;
    uint32_t acpt_maj;
    uint32_t acpt_min;
    struct gp_cred_check_handle gcch = {
        .ctx = gpcall,
        .options.options_len = arg->accept_sec_context.options.options_len,
        .options.options_val = arg->accept_sec_context.options.options_val,
    };
    uint32_t gccn_before = 0;
    uint32_t gccn_after = 0;
    int ret;

    asca = &arg->accept_sec_context;
    ascr = &res->accept_sec_context;

    GPRPCDEBUG(gssx_arg_accept_sec_context, asca);

    exp_ctx_type = gp_get_exported_context_type(&asca->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    exp_creds_type = gp_get_export_creds_type(&asca->call_ctx);
    if (exp_creds_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    if (asca->cred_handle) {
        ret_maj = gp_import_gssx_cred(&ret_min, gpcall,
                                      asca->cred_handle, &ach);
        if (ret_maj) {
            goto done;
        }

        gccn_before = gp_check_sync_creds(&gcch, ach);
    }

    if (ach == GSS_C_NO_CREDENTIAL) {
        ret_maj = gp_add_krb5_creds(&ret_min, gpcall,
                                    ACQ_NORMAL, NULL, NULL,
                                    GSS_C_ACCEPT,
                                    0, 0,
                                    &ach,
                                    NULL, NULL, NULL);
        if (ret_maj) {
            goto done;
        }
    }

    gp_conv_gssx_to_buffer(&asca->input_token, &ibuf);

    if (asca->input_cb) {
        pcbs = &cbs;
        gp_conv_gssx_to_cb(asca->input_cb, pcbs);
    } else {
        pcbs = GSS_C_NO_CHANNEL_BINDINGS;
    }

    if (asca->ret_deleg_cred) {
        pdch = &dch;
    }

    ret_maj = gss_accept_sec_context(&ret_min,
                                     &ctx,
                                     ach,
                                     &ibuf,
                                     pcbs,
                                     &src_name,
                                     &oid,
                                     &obuf,
                                     &ret_flags,
                                     NULL,
                                     pdch);
    if (ret_maj != GSS_S_COMPLETE &&
        ret_maj != GSS_S_CONTINUE_NEEDED) {
        goto done;
    } else {
        acpt_maj = ret_maj;
        acpt_min = ret_min;
    }
    if (acpt_maj == GSS_S_CONTINUE_NEEDED) {
        exp_ctx_type = gp_get_continue_needed_type();
    }


    ascr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!ascr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, oid,
                                       &ctx, ascr->context_handle);
    if (ret_maj) {
        goto done;
    }

    ascr->output_token = calloc(1, sizeof(gssx_buffer));
    if (!ascr->output_token) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&obuf, ascr->output_token);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    if ((ret_flags & GSS_C_DELEG_FLAG) && asca->ret_deleg_cred && dch) {
        ascr->delegated_cred_handle = calloc(1, sizeof(gssx_cred));
        if (!ascr->delegated_cred_handle) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ENOMEM;
            goto done;
        }
        ret_maj = gp_export_gssx_cred(&ret_min, gpcall,
                                      &dch, ascr->delegated_cred_handle);
        if (ret_maj) {
            goto done;
        }
    }

    ret_maj = gp_export_creds_to_gssx_options(&ret_min,
                                              exp_creds_type,
                                              src_name, oid,
                                              &ascr->options.options_len,
                                              &ascr->options.options_val);
    if (ret_maj) {
        goto done;
    }

    gccn_after = gp_check_sync_creds(&gcch, ach);

    if (gccn_before != gccn_after) {
        /* export creds back to client for sync up */
        ret_maj = gp_export_sync_creds(&ret_min, gpcall, &ach,
                                       &ascr->options.options_val,
                                       &ascr->options.options_len);
        if (ret_maj) {
            /* not fatal, log and continue */
            GPDEBUG("Failed to export sync creds (%d: %d)",
                    (int)ret_maj, (int)ret_min);
        }
    }

    ret_maj = GSS_S_COMPLETE;

done:
    if (ret_maj == GSS_S_COMPLETE) {
        ret_maj = acpt_maj;
        ret_min = acpt_min;
    }
    ret = gp_conv_status_to_gssx(ret_maj, ret_min, oid,
                                 &ascr->status);
    GPRPCDEBUG(gssx_res_accept_sec_context, ascr);

    gss_release_name(&ret_min, &src_name);
    gss_release_buffer(&ret_min, &obuf);
    gss_release_cred(&ret_min, &dch);
    gss_release_cred(&ret_min, &ach);
    gss_delete_sec_context(&ret_min, &ctx, GSS_C_NO_BUFFER);

    return ret;
}
