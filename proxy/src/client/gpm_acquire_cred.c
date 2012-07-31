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

#include "gssapi_gpm.h"

static int gpmint_cred_to_actual_mechs(gssx_cred *c, gss_OID_set *a)
{
    gssx_cred_element *e;
    gss_OID_set m = GSS_C_NO_OID_SET;
    int i;


    if (c->elements.elements_len) {

        m = malloc(sizeof(gss_OID_set_desc));
        if (!m) {
            return ENOMEM;
        }
        m->elements = calloc(c->elements.elements_len,
                             sizeof(gss_OID_desc));
        if (!m->elements) {
            free(m);
            return ENOMEM;
        }

        for (i = 0; i < c->elements.elements_len; i++) {
            e = &c->elements.elements_val[i];

            m->elements[i].elements = gp_memdup(e->mech.octet_string_val,
                                                e->mech.octet_string_len);
            if (!m->elements[i].elements) {
                while (i > 0) {
                    i--;
                    free(m->elements[i].elements);
                }
                free(m->elements);
                free(m);
                return ENOMEM;
            }
            m->elements[i].length = e->mech.octet_string_len;
        }
    }

    *a = m;
    return 0;
}

OM_uint32 gpm_acquire_cred(OM_uint32 *minor_status,
                           const gss_name_t desired_name,
                           OM_uint32 time_req,
                           const gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_acquire_cred *arg = &uarg.acquire_cred;
    gssx_res_acquire_cred *res = &ures.acquire_cred;
    uint32_t ret_min;
    uint32_t ret_maj;
    int ret = 0;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    if (output_cred_handle == NULL) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    /* ignore call_ctx for now */

    if (desired_name) {
        arg->desired_name = calloc(1, sizeof(gssx_name));
        if (!arg->desired_name) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ENOMEM;
            goto done;
        }
        ret_maj = gp_conv_name_to_gssx(&ret_min,
                                       desired_name, arg->desired_name);
        if (ret_maj) {
            goto done;
        }
    }
    if (desired_mechs) {
        ret = gp_conv_oid_set_to_gssx(desired_mechs, &arg->desired_mechs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    }
    arg->time_req = time_req;
    arg->cred_usage = gp_conv_cred_usage_to_gssx(cred_usage);

    /* execute proxy request */
    ret = gpm_make_call(GSSX_ACQUIRE_CRED, &uarg, &ures);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_min = res->status.minor_status;
        ret_maj = res->status.major_status;
        goto done;
    }

    if (actual_mechs) {
        ret = gpmint_cred_to_actual_mechs(res->output_cred_handle,
                                          actual_mechs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    }

    if (time_rec) {
        gssx_cred_element *e;
        uint32_t t = 0;

        if (res->output_cred_handle->elements.elements_len) {
            e = &res->output_cred_handle->elements.elements_val[0];
            if (e->initiator_time_rec < e->acceptor_time_rec) {
                t = e->initiator_time_rec;
            } else {
                t = e->acceptor_time_rec;
            }
        }

        *time_rec = t;
    }

    /* we steal the cred handler here */
    *output_cred_handle = (gss_cred_id_t)res->output_cred_handle;
    res->output_cred_handle = NULL;
    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    gpm_free_xdrs(GSSX_ACQUIRE_CRED, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_add_cred(OM_uint32 *minor_status,
                       const gss_cred_id_t input_cred_handle,
                       const gss_name_t desired_name,
                       const gss_OID desired_mech,
                       gss_cred_usage_t cred_usage,
                       OM_uint32 initiator_time_req,
                       OM_uint32 acceptor_time_req,
                       gss_cred_id_t *output_cred_handle,
                       gss_OID_set *actual_mechs,
                       OM_uint32 *initiator_time_rec,
                       OM_uint32 *acceptor_time_rec)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_acquire_cred *arg = &uarg.acquire_cred;
    gssx_res_acquire_cred *res = &ures.acquire_cred;
    gss_OID_set_desc mechs;
    uint32_t ret_min;
    uint32_t ret_maj;
    int ret = 0;

    memset(&uarg, 0, sizeof(union gp_rpc_arg));
    memset(&ures, 0, sizeof(union gp_rpc_res));

    /* ignore call_ctx for now */

    if (input_cred_handle) {
        arg->input_cred_handle = (gssx_cred *)input_cred_handle;
    }
    if (output_cred_handle != NULL) {
        arg->add_cred_to_input_handle = true;
    }
    if (desired_name != GSS_C_NO_NAME) {
        arg->desired_name = calloc(1, sizeof(gssx_name));
        if (!arg->desired_name) {
            ret = ENOMEM;
            goto done;
        }
        ret_maj = gp_conv_name_to_gssx(&ret_min,
                                       desired_name, arg->desired_name);
        if (ret_maj) {
            goto done;
        }
    }
    if (desired_mech != GSS_C_NO_OID) {
        mechs.count = 1;
        mechs.elements = desired_mech;
        ret = gp_conv_oid_set_to_gssx(&mechs, &arg->desired_mechs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    }
    arg->cred_usage = gp_conv_cred_usage_to_gssx(cred_usage);
    arg->initiator_time_req = initiator_time_req;
    arg->acceptor_time_req = acceptor_time_req;

    /* execute proxy request */
    ret = gpm_make_call(GSSX_ACQUIRE_CRED, &uarg, &ures);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_min = res->status.minor_status;
        ret_maj = res->status.major_status;
        goto done;
    }

    if (actual_mechs) {
        ret = gpmint_cred_to_actual_mechs(res->output_cred_handle,
                                          actual_mechs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    }

    if (res->output_cred_handle->elements.elements_len) {
        gssx_cred_element *e;
        e = &res->output_cred_handle->elements.elements_val[0];
        if (initiator_time_rec) {
            *initiator_time_rec = e->initiator_time_rec;
        }
        if (acceptor_time_rec) {
            *acceptor_time_rec = e->initiator_time_rec;
        }
    } else {
        if (initiator_time_rec) {
            *initiator_time_rec = 0;
        }
        if (acceptor_time_rec) {
            *acceptor_time_rec = 0;
        }
    }

    if (output_cred_handle) {
        /* we steal the cred handler here */
        *output_cred_handle = (gss_cred_id_t)res->output_cred_handle;
        res->output_cred_handle = NULL;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    gpm_free_xdrs(GSSX_ACQUIRE_CRED, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}
