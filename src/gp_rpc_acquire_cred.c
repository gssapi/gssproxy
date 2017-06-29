/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi_krb5.h>

int gp_acquire_cred(struct gp_call_ctx *gpcall,
                    union gp_rpc_arg *arg,
                    union gp_rpc_res *res)
{
    struct gssx_arg_acquire_cred *aca;
    struct gssx_res_acquire_cred *acr;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_cred_id_t in_cred = GSS_C_NO_CREDENTIAL;
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    gss_OID_set use_mechs = GSS_C_NO_OID_SET;
    gss_OID desired_mech = GSS_C_NO_OID;
    gss_cred_usage_t cred_usage;
    gss_cred_id_t out_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t *add_out_cred = NULL;
    int acquire_type = ACQ_NORMAL;
    int ret;

    aca = &arg->acquire_cred;
    acr = &res->acquire_cred;

    GPRPCDEBUG(gssx_arg_acquire_cred, aca);

    if (aca->input_cred_handle) {
        ret_maj = gp_import_gssx_cred(&ret_min, gpcall,
                                      aca->input_cred_handle, &in_cred);
        if (ret_maj) {
            goto done;
        }

        acquire_type = gp_get_acquire_type(aca);
        if (acquire_type == -1) {
            ret_maj = GSS_S_FAILURE;
            ret_min = EINVAL;
            goto done;
        }
    }

    if (aca->add_cred_to_input_handle) {
        add_out_cred = &in_cred;
    } else {
        add_out_cred = &out_cred;
    }

    ret = gp_conv_gssx_to_oid_set(&aca->desired_mechs, &desired_mechs);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* if a mech list is specified check if it includes the mechs
     * allowed by this service configuration */
    if (desired_mechs != GSS_C_NO_OID_SET) {
        ret_maj = gss_create_empty_oid_set(&ret_min, &use_mechs);
        if (ret_maj) {
            goto done;
        }

        for (unsigned i = 0; i < desired_mechs->count; i++) {
            desired_mech = &desired_mechs->elements[i];

            if (!gp_creds_allowed_mech(gpcall, desired_mech)) {
                continue;
            }

            ret_maj = gss_add_oid_set_member(&ret_min,
                                             desired_mech, &use_mechs);
            if (ret_maj) {
                goto done;
            }
        }

        if (use_mechs->count == 0) {
            /* no allowed mech, return nothing */
            desired_mech = GSS_C_NO_OID;
            ret_maj = GSS_S_NO_CRED;
            ret_min = 0;
            goto done;
        }
    } else {
        ret_maj = gp_get_supported_mechs(&ret_min, &use_mechs);
        if (ret_maj) {
            goto done;
        }
    }

    cred_usage = gp_conv_gssx_to_cred_usage(aca->cred_usage);

    for (unsigned i = 0; i < use_mechs->count; i++) {
        desired_mech = &use_mechs->elements[i];
        /* this should really be folded into an extended
         * gss_add_cred in gssapi that can accept a set of URIs
         * that define keytabs and ccaches and principals */
        if (gss_oid_equal(desired_mech, gss_mech_krb5)) {
            ret_maj = gp_add_krb5_creds(&ret_min,
                                        gpcall,
                                        acquire_type,
                                        in_cred,
                                        aca->desired_name,
                                        cred_usage,
                                        aca->initiator_time_req,
                                        aca->acceptor_time_req,
                                        add_out_cred,
                                        NULL,
                                        NULL,
                                        NULL);
            if (ret_maj) {
                goto done;
            }
        } else {
            /* we support only the krb5 mech for now */
            ret_maj = GSS_S_BAD_MECH;
            goto done;
        }
    }

    if (out_cred == GSS_C_NO_CREDENTIAL) {
        if (in_cred != GSS_C_NO_CREDENTIAL) {
            out_cred = in_cred;
        } else {
            ret_maj = GSS_S_NO_CRED;
            ret_min = 0;
            goto done;
        }
    }


    if (out_cred == in_cred) {
        acr->output_cred_handle = aca->input_cred_handle;
        aca->input_cred_handle = NULL;
    } else {
        acr->output_cred_handle = calloc(1, sizeof(gssx_cred));
        if (!acr->output_cred_handle) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ENOMEM;
            goto done;
        }

        ret_maj = gp_export_gssx_cred(&ret_min, gpcall,
                                      &out_cred, acr->output_cred_handle);
        if (ret_maj) {
            goto done;
        }
    }

done:
    ret = gp_conv_status_to_gssx(ret_maj, ret_min, desired_mech,
                                 &acr->status);

    GPRPCDEBUG(gssx_res_acquire_cred, acr);

    if (add_out_cred != &in_cred && add_out_cred != &out_cred)
        gss_release_cred(&ret_min, add_out_cred);
    if (in_cred != out_cred)
        gss_release_cred(&ret_min, &in_cred);
    gss_release_cred(&ret_min, &out_cred);
    gss_release_oid_set(&ret_min, &use_mechs);
    gss_release_oid_set(&ret_min, &desired_mechs);
    return ret;
}
