/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi_krb5.h>

int gp_init_sec_context(struct gp_call_ctx *gpcall,
                        union gp_rpc_arg *arg,
                        union gp_rpc_res *res)
{
    struct gssx_arg_init_sec_context *isca;
    struct gssx_res_init_sec_context *iscr;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t ich = GSS_C_NO_CREDENTIAL;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_OID mech_type = GSS_C_NO_OID;
    uint32_t req_flags;
    uint32_t time_req;
    struct gss_channel_bindings_struct cbs;
    gss_channel_bindings_t pcbs;
    gss_buffer_desc ibuf = { 0, NULL };
    gss_buffer_t pibuf = &ibuf;
    gss_OID actual_mech_type = GSS_C_NO_OID;
    gss_buffer_desc obuf = GSS_C_EMPTY_BUFFER;
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t init_maj;
    uint32_t init_min;
    int exp_ctx_type;
    struct gp_cred_check_handle gcch = {
        .ctx = gpcall,
        .options.options_len = arg->init_sec_context.options.options_len,
        .options.options_val = arg->init_sec_context.options.options_val,
    };
    uint32_t gccn_before = 0;
    uint32_t gccn_after = 0;
    int ret;

    isca = &arg->init_sec_context;
    iscr = &res->init_sec_context;

    GPRPCDEBUG(gssx_arg_init_sec_context, isca);

    exp_ctx_type = gp_get_exported_context_type(&isca->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    if (isca->context_handle) {
        ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                           isca->context_handle, &ctx);
        if (ret_maj) {
            goto done;
        }
    }

    if (isca->cred_handle) {
        ret_maj = gp_import_gssx_cred(&ret_min, gpcall,
                                      isca->cred_handle, &ich);
        if (ret_maj) {
            goto done;
        }

        gccn_before = gp_check_sync_creds(&gcch, ich);
    }

    ret_maj = gp_conv_gssx_to_name(&ret_min, isca->target_name, &target_name);
    if (ret_maj) {
        goto done;
    }

    ret = gp_conv_gssx_to_oid_alloc(&isca->mech_type, &mech_type);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    req_flags = isca->req_flags;
    time_req = isca->time_req;

    if (isca->input_cb) {
        pcbs = &cbs;
        gp_conv_gssx_to_cb(isca->input_cb, pcbs);
    } else {
        pcbs = GSS_C_NO_CHANNEL_BINDINGS;
    }

    if (isca->input_token) {
        gp_conv_gssx_to_buffer(isca->input_token, &ibuf);
    }

    if (!isca->cred_handle) {
        if (gss_oid_equal(mech_type, gss_mech_krb5)) {
            ret_maj = gp_add_krb5_creds(&ret_min, gpcall,
                                        ACQ_NORMAL, NULL, NULL,
                                        GSS_C_INITIATE,
                                        time_req, 0, &ich,
                                        NULL, NULL, NULL);
        } else {
            ret_maj = GSS_S_NO_CRED;
            ret_min = 0;
        }

        if (ret_maj) {
            goto done;
        }
    }

    ret_maj = gp_cred_allowed(&ret_min, gpcall, ich, target_name);
    if (ret_maj) {
        goto done;
    }

    gp_filter_flags(gpcall, &req_flags);

    ret_maj = gss_init_sec_context(&ret_min,
                                   ich,
                                   &ctx,
                                   target_name,
                                   mech_type,
                                   req_flags,
                                   time_req,
                                   pcbs,
                                   pibuf,
                                   &actual_mech_type,
                                   &obuf,
                                   NULL,
                                   NULL);
    if (ret_maj != GSS_S_COMPLETE &&
        ret_maj != GSS_S_CONTINUE_NEEDED) {
        goto done;
    } else {
        init_maj = ret_maj;
        init_min = ret_min;
    }
    if (init_maj == GSS_S_CONTINUE_NEEDED) {
        exp_ctx_type = gp_get_continue_needed_type();
    }

    iscr->context_handle = calloc(1, sizeof(gssx_ctx));
    if (!iscr->context_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret_maj = gp_export_ctx_id_to_gssx(&ret_min, exp_ctx_type, mech_type,
                                       &ctx, iscr->context_handle);
    if (ret_maj) {
        goto done;
    }

    if (obuf.length != 0) {
        iscr->output_token = calloc(1, sizeof(gssx_buffer));
        if (!iscr->output_token) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ENOMEM;
            goto done;
        }
        ret = gp_conv_buffer_to_gssx(&obuf, iscr->output_token);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    }

    gccn_after = gp_check_sync_creds(&gcch, ich);

    if (gccn_before != gccn_after) {
        /* export creds back to client for sync up */
        ret_maj = gp_export_sync_creds(&ret_min, gpcall, &ich,
                                       &iscr->options.options_val,
                                       &iscr->options.options_len);
        if (ret_maj) {
            /* not fatal, log and continue */
            GPDEBUG("Failed to export sync creds (%d: %d)",
                    (int)ret_maj, (int)ret_min);
        }
    }

    ret_maj = GSS_S_COMPLETE;

done:
    if (ret_maj == GSS_S_COMPLETE) {
        ret_maj = init_maj;
        ret_min = init_min;
    }
    ret = gp_conv_status_to_gssx(&isca->call_ctx,
                                 ret_maj, ret_min, mech_type,
                                 &iscr->status);

    GPRPCDEBUG(gssx_res_init_sec_context, iscr);

    gss_release_name(&ret_min, &target_name);
    gss_release_oid(&ret_min, &mech_type);
    gss_release_cred(&ret_min, &ich);
    gss_release_buffer(&ret_min, &obuf);
    return ret;
}
