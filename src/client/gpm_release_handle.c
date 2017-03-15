/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"

OM_uint32 gpm_release_cred(OM_uint32 *minor_status,
                           gssx_cred **cred_handle)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_release_handle *arg = &uarg.release_handle;
    gssx_res_release_handle *res = &ures.release_handle;
    gssx_cred *r;
    int ret;

    if (cred_handle == NULL || *cred_handle == NULL) {
        return 0;
    }

    r = (*cred_handle);

    if (!r->needs_release) {
        ret = GSS_S_COMPLETE;
        goto done;
    }

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    /* ignore call_ctx for now */

    arg->cred_handle.handle_type = GSSX_C_HANDLE_CRED;
    arg->cred_handle.gssx_handle_u.cred_info = *r;

    /* execute proxy request */
    ret = gpm_make_call(GSSX_RELEASE_HANDLE, &uarg, &ures);
    if (ret) {
        *minor_status = ret;
        ret = GSS_S_FAILURE;
        goto rel_done;
    }

    if (res->status.major_status) {
        gpm_save_status(&res->status);
        *minor_status = res->status.minor_status;
        ret = res->status.major_status;
    }

rel_done:
    /* we passed in our copy by value, so clean out to avoid double frees */
    memset(&arg->cred_handle.gssx_handle_u.cred_info, 0, sizeof(gssx_cred));
    gpm_free_xdrs(GSSX_RELEASE_HANDLE, &uarg, &ures);
done:
    xdr_free((xdrproc_t)xdr_gssx_cred, (char *)r);
    free(r);
    *cred_handle = NULL;
    return ret;
}

OM_uint32 gpm_delete_sec_context(OM_uint32 *minor_status,
                                 gssx_ctx **context_handle,
                                 gss_buffer_t output_token UNUSED)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_release_handle *arg = &uarg.release_handle;
    gssx_res_release_handle *res = &ures.release_handle;
    gssx_ctx *r;
    int ret;

    if (context_handle == NULL || *context_handle == NULL) {
        return 0;
    }

    r = (*context_handle);

    if (!r->needs_release) {
        ret = GSS_S_COMPLETE;
        goto done;
    }

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    /* ignore call_ctx for now */

    arg->cred_handle.handle_type = GSSX_C_HANDLE_SEC_CTX;
    arg->cred_handle.gssx_handle_u.sec_ctx_info = *r;

    /* execute proxy request */
    ret = gpm_make_call(GSSX_RELEASE_HANDLE, &uarg, &ures);
    if (ret) {
        *minor_status = ret;
        ret = GSS_S_FAILURE;
        goto rel_done;
    }

    if (res->status.major_status) {
        gpm_save_status(&res->status);
        *minor_status = res->status.minor_status;
        ret = res->status.major_status;
    }

rel_done:
    /* we passed in our copy by value, so clean out to avoid double frees */
    memset(&arg->cred_handle.gssx_handle_u.sec_ctx_info, 0, sizeof(gssx_cred));
    gpm_free_xdrs(GSSX_RELEASE_HANDLE, &uarg, &ures);
done:
    xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)r);
    return ret;
}
