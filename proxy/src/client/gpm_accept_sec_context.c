/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"
#include "src/gp_conv.h"

OM_uint32 gpm_accept_sec_context(OM_uint32 *minor_status,
                                 gssx_ctx **context_handle,
                                 gssx_cred *acceptor_cred_handle,
                                 gss_buffer_t input_token_buffer,
                                 gss_channel_bindings_t input_chan_bindings,
                                 gssx_name **src_name,
                                 gss_OID *mech_type,
                                 gss_buffer_t output_token,
                                 OM_uint32 *ret_flags,
                                 OM_uint32 *time_rec,
                                 gssx_cred **delegated_cred_handle)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_accept_sec_context *arg = &uarg.accept_sec_context;
    gssx_res_accept_sec_context *res = &ures.accept_sec_context;
    gssx_ctx *ctx = NULL;
    gssx_name *name = NULL;
    gss_OID_desc *mech = NULL;
    gss_buffer_t outbuf = NULL;
    uint32_t ret_maj;
    int ret;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    /* prepare proxy request */
    if (*context_handle) {
        arg->context_handle = *context_handle;
    }

    if (acceptor_cred_handle) {
        arg->cred_handle = acceptor_cred_handle;
    }

    ret = gp_conv_buffer_to_gssx(input_token_buffer, &arg->input_token);
    if (ret) {
        goto done;
    }

    if (input_chan_bindings) {
        ret = gp_conv_cb_to_gssx_alloc(input_chan_bindings, &arg->input_cb);
        if (ret) {
            goto done;
        }
    }

    /* check if we want delegated creds */
    if (delegated_cred_handle) {
        arg->ret_deleg_cred = true;
    }

    /* execute proxy request */
    ret = gpm_make_call(GSSX_ACCEPT_SEC_CONTEXT, &uarg, &ures);
    if (ret) {
        goto done;
    }

    /* return values */
    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_maj = res->status.major_status;
        *minor_status = res->status.minor_status;
        ret = 0;
        goto done;
    }

    if (mech_type) {
        if (res->status.mech.octet_string_len) {
            ret = gp_conv_gssx_to_oid_alloc(&res->status.mech, &mech);
            if (ret) {
                goto done;
            }
        }
    }

    ctx = res->context_handle;
    /* we are stealing the delegated creds on success, so we do not want
     * it to be freed by xdr_free */
    res->context_handle = NULL;
    if (ctx == NULL) {
        ret = EINVAL;
        goto done;
    }

    if (src_name) {
        ret = gp_copy_gssx_name_alloc(&ctx->src_name, &name);
        if (ret) {
            goto done;
        }
    }

    ret = gp_conv_gssx_to_buffer_alloc(res->output_token, &outbuf);
    if (ret) {
        goto done;
    }

    if (mech_type) {
        *mech_type = mech;
    }
    if (src_name) {
        *src_name = name;
    }
    if (outbuf) {
        *output_token = *outbuf;
        free(outbuf);
    }
    if (ret_flags) {
        *ret_flags = ctx->ctx_flags;
    }
    if (time_rec) {
        *time_rec = ctx->lifetime;
    }

    if (res->delegated_cred_handle) {
        if (delegated_cred_handle) {
            *delegated_cred_handle = res->delegated_cred_handle;
        }
        /* we are stealing the delegated creds on success, so we do not want
        * it to be freed by xdr_free */
        res->delegated_cred_handle = NULL;
    }

    *minor_status = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    /* we are putting our copy of these structures in here,
     * and do not want it to be freed by xdr_free */
    arg->context_handle = NULL;
    arg->cred_handle = NULL;
    gpm_free_xdrs(GSSX_ACCEPT_SEC_CONTEXT, &uarg, &ures);

    if (ret) {
        if (ctx) {
            xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)ctx);
            free(ctx);
        }
        if (name) {
            xdr_free((xdrproc_t)xdr_gssx_name, (char *)name);
            free(name);
        }
        if (mech) {
            free(mech->elements);
            free(mech);
        }
        if (outbuf) {
            free(outbuf->value);
            free(outbuf);
        }
        *minor_status = ret;
        return GSS_S_FAILURE;
    }

    /* always replace old ctx handle and set new */
    if (*context_handle) {
        xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)*context_handle);
        free(*context_handle);
    }
    *context_handle = ctx;

    return ret_maj;
}

