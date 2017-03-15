/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"

static int gpmint_cred_to_actual_mechs(gssx_cred *c, gss_OID_set *a)
{
    gssx_cred_element *e;
    gss_OID_set m = GSS_C_NO_OID_SET;

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

        for (unsigned i = 0; i < c->elements.elements_len; i++) {
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
                           gssx_cred *in_cred_handle,
                           gssx_name *desired_name,
                           OM_uint32 time_req,
                           const gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           bool impersonate,
                           gssx_cred **output_cred_handle,
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

    arg->input_cred_handle = in_cred_handle;
    arg->desired_name = desired_name;

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

    /* impersonate calls use input cred and a special option */
    if (impersonate) {
        ret_min = gp_add_option(&arg->options.options_val,
                                &arg->options.options_len,
                                ACQUIRE_TYPE_OPTION,
                                sizeof(ACQUIRE_TYPE_OPTION),
                                ACQUIRE_IMPERSONATE_NAME,
                                sizeof(ACQUIRE_IMPERSONATE_NAME));
        if (ret_min) {
            ret_maj = GSS_S_FAILURE;
            goto done;
        }
    }

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
    *output_cred_handle = res->output_cred_handle;
    res->output_cred_handle = NULL;
    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    /* don't let gpm_free_xdrs free variables passed in */
    arg->desired_name = NULL;
    arg->input_cred_handle = NULL;
    gpm_free_xdrs(GSSX_ACQUIRE_CRED, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_add_cred(OM_uint32 *minor_status,
                       gssx_cred *input_cred_handle,
                       gssx_name *desired_name,
                       const gss_OID desired_mech,
                       gss_cred_usage_t cred_usage,
                       OM_uint32 initiator_time_req,
                       OM_uint32 acceptor_time_req,
                       gssx_cred **output_cred_handle,
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
        arg->input_cred_handle = input_cred_handle;
    }
    if (output_cred_handle != NULL) {
        arg->add_cred_to_input_handle = true;
    }

    arg->desired_name = desired_name;

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
        *output_cred_handle = res->output_cred_handle;
        res->output_cred_handle = NULL;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    gpm_free_xdrs(GSSX_ACQUIRE_CRED, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_inquire_cred(OM_uint32 *minor_status,
                           gssx_cred *cred,
                           gssx_name **name,
                           OM_uint32 *lifetime,
                           gss_cred_usage_t *cred_usage,
                           gss_OID_set *mechanisms)
{
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gssx_name *dname = NULL;
    gssx_cred_element *e;
    gss_OID_desc tmp_oid;
    uint32_t ret_min = 0;
    uint32_t ret_maj = GSS_S_COMPLETE;
    uint32_t life;
    int cu;

    if (!cred) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (cred->elements.elements_len == 0) {
        *minor_status = 0;
        return GSS_S_FAILURE;
    }

    if (name) {
        ret_min = gp_copy_gssx_name_alloc(&cred->desired_name, &dname);
        if (ret_min != 0) {
            return GSS_S_FAILURE;
        }
    }

    if (mechanisms) {
        ret_maj = gss_create_empty_oid_set(&ret_min, &mechs);
        if (ret_maj) {
            goto done;
        }
    }

    life = GSS_C_INDEFINITE;
    cu = -1;

    for (unsigned i = 0; i < cred->elements.elements_len; i++) {
        e = &cred->elements.elements_val[i];

        switch (e->cred_usage) {
        case GSSX_C_INITIATE:
            if (e->initiator_time_rec != 0 &&
                e->initiator_time_rec < life) {
                life = e->initiator_time_rec;
            }
            switch (cu) {
            case GSS_C_BOTH:
                break;
            case GSS_C_ACCEPT:
                cu = GSS_C_BOTH;
                break;
            default:
                cu = GSS_C_INITIATE;
            }
            break;
        case GSSX_C_ACCEPT:
            if (e->acceptor_time_rec != 0 &&
                e->acceptor_time_rec < life) {
                life = e->acceptor_time_rec;
            }
            switch (cu) {
            case GSS_C_BOTH:
                break;
            case GSS_C_INITIATE:
                cu = GSS_C_BOTH;
                break;
            default:
                cu = GSS_C_ACCEPT;
            }
            break;
        case GSSX_C_BOTH:
            if (e->initiator_time_rec != 0 &&
                e->initiator_time_rec < life) {
                life = e->initiator_time_rec;
            }
            if (e->acceptor_time_rec != 0 &&
                e->acceptor_time_rec < life) {
                life = e->acceptor_time_rec;
            }
            cu = GSS_C_BOTH;
            break;
        }

        if (mechanisms) {
            gp_conv_gssx_to_oid(&e->mech, &tmp_oid);
            ret_maj = gss_add_oid_set_member(&ret_min, &tmp_oid, &mechs);
            if (ret_maj) {
                goto done;
            }
        }
    }

    if (lifetime) {
        *lifetime = life;
    }

    if (cred_usage) {
        *cred_usage = cu;
    }

done:
    *minor_status = ret_min;
    if (ret_maj == GSS_S_COMPLETE) {
        if (name) {
            *name = dname;
        }
        if (mechanisms) {
            *mechanisms = mechs;
        }
    } else {
        (void)gpm_release_name(&ret_min, &dname);
        (void)gss_release_oid_set(&ret_min, &mechs);
    }
    return ret_maj;
}

OM_uint32 gpm_inquire_cred_by_mech(OM_uint32 *minor_status,
                                   gssx_cred *cred,
                                   gss_OID mech_type,
                                   gssx_name **name,
                                   OM_uint32 *initiator_lifetime,
                                   OM_uint32 *acceptor_lifetime,
                                   gss_cred_usage_t *cred_usage)
{
    gssx_name *dname = NULL;
    gssx_cred_element *e;
    gss_OID_desc tmp_oid;
    uint32_t ret_min = 0;
    uint32_t ret_maj = GSS_S_COMPLETE;
    unsigned i;

    if (!cred) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (cred->elements.elements_len == 0) {
        *minor_status = 0;
        return GSS_S_FAILURE;
    }

    for (i = 0; i < cred->elements.elements_len; i++) {
        e = &cred->elements.elements_val[i];
        gp_conv_gssx_to_oid(&e->mech, &tmp_oid);
        if (!gss_oid_equal(&tmp_oid, mech_type)) {
            continue;
        }

        switch (e->cred_usage) {
        case GSSX_C_INITIATE:
            if (initiator_lifetime) {
                *initiator_lifetime = e->initiator_time_rec;
            }
            if (cred_usage) {
                *cred_usage = GSS_C_INITIATE;
            }
            break;
        case GSSX_C_ACCEPT:
            if (acceptor_lifetime) {
                *acceptor_lifetime = e->acceptor_time_rec;
            }
            if (cred_usage) {
                *cred_usage = GSS_C_ACCEPT;
            }
            break;
        case GSSX_C_BOTH:
            if (initiator_lifetime) {
                *initiator_lifetime = e->initiator_time_rec;
            }
            if (acceptor_lifetime) {
                *acceptor_lifetime = e->acceptor_time_rec;
            }
            if (cred_usage) {
                *cred_usage = GSS_C_BOTH;
            }
            break;
        }
        if (name) {
            ret_min = gp_copy_gssx_name_alloc(&e->MN, &dname);
            if (ret_min != 0) {
                ret_maj = GSS_S_FAILURE;
                goto done;
            }
            *name = dname;
        }
        goto done;
    }

    if (i >= cred->elements.elements_len) {
        ret_maj = GSS_S_FAILURE;
    }

done:
    *minor_status = ret_min;
    if (ret_maj != GSS_S_COMPLETE) {
        (void)gpm_release_name(&ret_min, &dname);
    }
    return ret_maj;
}

