/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "gp_rpc_process.h"
#include <gssapi/gssapi_krb5.h>

int gp_acquire_cred(struct gssproxy_ctx *gpctx,
                    struct gp_service *gpsvc,
                    union gp_rpc_arg *arg,
                    union gp_rpc_res *res)
{
    struct gssx_arg_acquire_cred *aca;
    struct gssx_res_acquire_cred *acr;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_cred_id_t in_cred = GSS_C_NO_CREDENTIAL;
    gss_name_t desired_name = GSS_C_NO_NAME;
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    gss_OID_set use_mechs = GSS_C_NO_OID_SET;
    gss_OID desired_mech = GSS_C_NO_OID;
    gss_cred_usage_t cred_usage;
    gss_cred_id_t out_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t *add_out_cred = NULL;
    int ret;
    int i;

    aca = &arg->acquire_cred;
    acr = &res->acquire_cred;

    if (aca->input_cred_handle) {
        ret = gp_find_cred(aca->input_cred_handle, &in_cred);
        if (ret) {
            ret_maj = GSS_S_NO_CRED;
            ret_min = ret;
            goto done;
        }
    }

    if (aca->add_cred_to_input_handle) {
        add_out_cred = &in_cred;
    } else {
        add_out_cred = &out_cred;
    }

    if (aca->desired_name) {
        ret_maj = gp_conv_gssx_to_name(&ret_min,
                                       aca->desired_name, &desired_name);
        if (ret_maj) {
            goto done;
        }
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

        for (i = 0; i < desired_mechs->count; i++) {
            desired_mech = &desired_mechs->elements[i];

            if (!gp_creds_allowed_mech(gpsvc, desired_mech)) {
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
        ret_maj = gp_get_supported_mechs(&ret_min, gpsvc, &use_mechs);
        if (ret_maj) {
            goto done;
        }
    }

    cred_usage = gp_conv_gssx_to_cred_usage(aca->cred_usage);

    for (i = 0; i < use_mechs->count; i++) {
        desired_mech = &use_mechs->elements[i];
        /* this should really be folded into an extended
         * gss_add_cred in gssapi that can accept a set of URIs
         * that define keytabs and ccaches and principals */
        if (gss_oid_equal(desired_mech, gss_mech_krb5)) {
            ret_maj = gp_add_krb5_creds(&ret_min,
                                        gpsvc,
                                        in_cred,
                                        desired_name,
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
            ret_maj = gss_add_cred(&ret_min,
                                   in_cred,
                                   desired_name,
                                   desired_mech,
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

    acr->output_cred_handle = calloc(1, sizeof(gssx_cred));
    if (!acr->output_cred_handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret_maj = gp_export_gssx_cred(&ret_min, &out_cred, acr->output_cred_handle);
    if (ret_maj) {
        goto done;
    }

done:
    ret = gp_conv_status_to_gssx(&aca->call_ctx,
                                 ret_maj, ret_min, desired_mech,
                                 &acr->status);

    gss_release_cred(&ret_min, &out_cred);
    gss_release_oid_set(&ret_min, &use_mechs);
    return ret;
}
