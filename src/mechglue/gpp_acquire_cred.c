/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"

static OM_uint32 acquire_local(OM_uint32 *minor_status,
                               struct gpp_cred_handle *imp_cred_handle,
                               struct gpp_name_handle *name,
                               OM_uint32 time_req,
                               const gss_OID_set desired_mechs,
                               gss_cred_usage_t cred_usage,
                               gss_const_key_value_set_t cred_store,
                               struct gpp_cred_handle *out_cred_handle,
                               gss_OID_set *actual_mechs,
                               OM_uint32 *time_rec)
{
    gss_OID_set special_mechs = GSS_C_NO_OID_SET;
    OM_uint32 maj, min;

    special_mechs = gpp_special_available_mechs(desired_mechs);
    if (special_mechs == GSS_C_NO_OID_SET) {
        maj = GSS_S_BAD_MECH;
        min = 0;
        goto done;
    }

    if (name && name->remote && !name->local) {
        maj = gpp_name_to_local(&min, name->remote,
                                name->mech_type, &name->local);
        if (maj) {
            goto done;
        }
    }

    if (imp_cred_handle) {
        maj = gss_acquire_cred_impersonate_name(&min,
                                                imp_cred_handle->local,
                                                name ? name->local : NULL,
                                                time_req,
                                                special_mechs,
                                                cred_usage,
                                                &out_cred_handle->local,
                                                actual_mechs,
                                                time_rec);
        goto done;
    }

    maj = gss_acquire_cred_from(&min,
                                name ? name->local : NULL,
                                time_req,
                                special_mechs,
                                cred_usage,
                                cred_store,
                                &out_cred_handle->local,
                                actual_mechs,
                                time_rec);

done:
    *minor_status = min;
    (void)gss_release_oid_set(&min, &special_mechs);
    return maj;
}

OM_uint32 gssi_acquire_cred(OM_uint32 *minor_status,
                            const gss_name_t desired_name,
                            OM_uint32 time_req,
                            const gss_OID_set desired_mechs,
                            gss_cred_usage_t cred_usage,
                            gss_cred_id_t *output_cred_handle,
                            gss_OID_set *actual_mechs,
                            OM_uint32 *time_rec)
{
    return gssi_acquire_cred_from(minor_status, desired_name, time_req,
                                  desired_mechs, cred_usage, NULL,
                                  output_cred_handle, actual_mechs, time_rec);
}

OM_uint32 gssi_acquire_cred_from(OM_uint32 *minor_status,
                                 const gss_name_t desired_name,
                                 OM_uint32 time_req,
                                 const gss_OID_set desired_mechs,
                                 gss_cred_usage_t cred_usage,
                                 gss_const_key_value_set_t cred_store,
                                 gss_cred_id_t *output_cred_handle,
                                 gss_OID_set *actual_mechs,
                                 OM_uint32 *time_rec)
{
    enum gpp_behavior behavior;
    struct gpp_name_handle *name;
    struct gpp_cred_handle *out_cred_handle = NULL;
    struct gssx_cred *in_cred_remote = NULL;
    const char *ccache_name = NULL;
    OM_uint32 maj, min;
    OM_uint32 tmaj, tmin;

    GSSI_TRACE();

    if (!output_cred_handle) {
        *minor_status = gpp_map_error(EINVAL);
        return GSS_S_FAILURE;
    }

    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    name = (struct gpp_name_handle *)desired_name;
    behavior = gpp_get_behavior();

    /* Always check if we have remote creds stored in the local ccache */
    for (unsigned i = 0; cred_store && i < cred_store->count; i++) {
        if (strcmp(cred_store->elements[i].key, "ccache") == 0) {
            ccache_name = cred_store->elements[i].value;
            break;
        }
    }

    maj = gpp_cred_handle_init(&min, !ccache_name, ccache_name,
                               &out_cred_handle);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    if (behavior != GPP_LOCAL_ONLY) {
        in_cred_remote = calloc(1, sizeof(gssx_cred));
        if (!in_cred_remote) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
        maj = gppint_retrieve_remote_creds(&min, ccache_name, NULL,
                                           in_cred_remote);
        if (maj == GSS_S_COMPLETE) {
            behavior = GPP_REMOTE_FIRST;
        } else {
            safefree(in_cred_remote);
            if (ccache_name) {
                behavior = GPP_LOCAL_FIRST;
            }
        }
    }

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = acquire_local(&min, NULL, name,
                            time_req, desired_mechs, cred_usage, cred_store,
                            out_cred_handle, actual_mechs, time_rec);

        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (name && name->local && !name->remote) {
        maj = gpp_local_to_name(&min, name->local, &name->remote);
        if (maj) {
            goto done;
        }
    }

    maj = gpm_acquire_cred(&min, in_cred_remote,
                           name ? name->remote : NULL,
                           time_req,
                           desired_mechs,
                           cred_usage, false,
                           &out_cred_handle->remote,
                           actual_mechs,
                           time_rec);
    if (maj == GSS_S_COMPLETE) {
        /* store back creds if they changed */
        if (out_cred_handle->remote &&
            !gpp_creds_are_equal(in_cred_remote, out_cred_handle->remote)) {
            tmaj = gpp_store_remote_creds(&tmin,
                                          out_cred_handle->default_creds,
                                          &out_cred_handle->store,
                                          out_cred_handle->remote);
            if (tmaj != GSS_S_COMPLETE) {
                maj = tmaj;
            }
        }
        goto done;
    }

    if (behavior == GPP_REMOTE_FIRST) {
        if (maj != GSS_S_COMPLETE) {
            /* save errors */
            tmaj = maj;
            tmin = min;
        }
        /* So remote failed, but we can fallback to local, try that */
        maj = acquire_local(&min, NULL, name,
                            time_req, desired_mechs, cred_usage, cred_store,
                            out_cred_handle, actual_mechs, time_rec);
    }

done:
    if (maj != GSS_S_COMPLETE &&
        maj != GSS_S_CONTINUE_NEEDED &&
        tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    if (in_cred_remote) {
        xdr_free((xdrproc_t)xdr_gssx_cred, (char *)in_cred_remote);
        free(in_cred_remote);
    }
    if (maj == GSS_S_COMPLETE) {
        *output_cred_handle = (gss_cred_id_t)out_cred_handle;
    } else {
        (void)gpp_cred_handle_free(&tmin, out_cred_handle);
    }
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_add_cred(OM_uint32 *minor_status,
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
    return gssi_add_cred_from(minor_status, input_cred_handle, desired_name,
                              desired_mech, cred_usage, initiator_time_req,
                              acceptor_time_req, NULL, output_cred_handle,
                              actual_mechs, initiator_time_rec,
                              acceptor_time_rec);
}

OM_uint32 gssi_add_cred_from(OM_uint32 *minor_status,
                             const gss_cred_id_t input_cred_handle,
                             const gss_name_t desired_name,
                             const gss_OID desired_mech,
                             gss_cred_usage_t cred_usage,
                             OM_uint32 initiator_time_req,
                             OM_uint32 acceptor_time_req,
                             gss_const_key_value_set_t cred_store,
                             gss_cred_id_t *output_cred_handle,
                             gss_OID_set *actual_mechs,
                             OM_uint32 *initiator_time_rec,
                             OM_uint32 *acceptor_time_rec)
{
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    OM_uint32 time_req, time_rec;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (!output_cred_handle) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (desired_mech) {
        maj = gss_create_empty_oid_set(&min, &desired_mechs);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
        maj = gss_add_oid_set_member(&min, desired_mech, &desired_mechs);
        if (maj != GSS_S_COMPLETE) {
            (void)gss_release_oid_set(&min, &desired_mechs);
            *minor_status = gpp_map_error(min);
            return maj;
        }
    }

    switch (cred_usage) {
    case GSS_C_ACCEPT:
        time_req = acceptor_time_req;
        break;
    case GSS_C_INITIATE:
        time_req = initiator_time_req;
        break;
    case GSS_C_BOTH:
        if (acceptor_time_req > initiator_time_req) {
            time_req = acceptor_time_req;
        } else {
            time_req = initiator_time_req;
        }
        break;
    default:
        time_req = 0;
    }

    maj = gssi_acquire_cred_from(minor_status, desired_name, time_req,
                                 desired_mechs, cred_usage, NULL,
                                 output_cred_handle, actual_mechs, &time_rec);
    if (maj == GSS_S_COMPLETE) {
        if (acceptor_time_rec &&
            (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH)) {
            *acceptor_time_rec = time_rec;
        }
        if (initiator_time_rec &&
            (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH)) {
            *initiator_time_rec = time_rec;
        }
    }

    (void)gss_release_oid_set(&min, &desired_mechs);
    return maj;
}

OM_uint32 gssi_acquire_cred_with_password(OM_uint32 *minor_status,
                                          const gss_name_t desired_name,
                                          const gss_buffer_t password,
                                          OM_uint32 time_req,
                                          const gss_OID_set desired_mechs,
                                          gss_cred_usage_t cred_usage,
                                          gss_cred_id_t *output_cred_handle,
                                          gss_OID_set *actual_mechs,
                                          OM_uint32 *time_rec)
{
    enum gpp_behavior behavior;
    struct gpp_name_handle *name;
    struct gpp_cred_handle *out_cred_handle = NULL;
    gss_OID_set special_mechs;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (desired_name == GSS_C_NO_NAME) {
        *minor_status = gpp_map_error(EINVAL);
        return GSS_S_BAD_NAME;
    }
    name = (struct gpp_name_handle *)desired_name;

    if (!output_cred_handle) {
        *minor_status = gpp_map_error(EINVAL);
        return GSS_S_FAILURE;
    }

    if (desired_mechs == GSS_C_NO_OID_SET) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    behavior = gpp_get_behavior();

    maj = gpp_cred_handle_init(&min, false, NULL, &out_cred_handle);
    if (maj != GSS_S_COMPLETE) {
        *minor_status = gpp_map_error(min);
        return maj;
    }

    switch (behavior) {
    case GPP_LOCAL_ONLY:
    case GPP_LOCAL_FIRST:
    case GPP_REMOTE_FIRST:

        /* re-enter the mechglue, using the special OIDs for skipping
         * the use of the interposer */
        special_mechs = gpp_special_available_mechs(desired_mechs);
        if (special_mechs == GSS_C_NO_OID_SET) {
            min = EINVAL;
            maj = GSS_S_FAILURE;
            goto done;
        }

        if (name->remote && !name->local) {
            maj = gpp_name_to_local(&min, name->remote,
                                    name->mech_type, &name->local);
            if (maj) {
                goto done;
            }
        }

        maj = gss_acquire_cred_with_password(&min,
                                             name->local,
                                             password,
                                             time_req,
                                             special_mechs,
                                             cred_usage,
                                             &out_cred_handle->local,
                                             actual_mechs,
                                             time_rec);
        break;
        /* fall through if we got no creds locally and we are in
         * automatic mode */

    case GPP_REMOTE_ONLY:

        /* FIXME: not currently available */

        /* fall through for now */

    default:
        maj = GSS_S_FAILURE;
        min = EINVAL;
    }

done:
    if (maj == GSS_S_COMPLETE) {
        *output_cred_handle = (gss_cred_id_t)out_cred_handle;
    } else {
        free(out_cred_handle);
    }
    *minor_status = gpp_map_error(min);
    (void)gss_release_oid_set(&min, &special_mechs);
    return maj;
}

OM_uint32 gssi_acquire_cred_impersonate_name(OM_uint32 *minor_status,
                                             gss_cred_id_t *imp_cred_handle,
                                             const gss_name_t desired_name,
                                             OM_uint32 time_req,
                                             const gss_OID_set desired_mechs,
                                             gss_cred_usage_t cred_usage,
                                             gss_cred_id_t *output_cred_handle,
                                             gss_OID_set *actual_mechs,
                                             OM_uint32 *time_rec)
{
    enum gpp_behavior behavior;
    struct gpp_name_handle *name;
    struct gpp_cred_handle *impersonator_cred_handle = NULL;
    struct gpp_cred_handle *out_cred_handle = NULL;
    OM_uint32 maj, min;
    OM_uint32 tmaj, tmin;

    GSSI_TRACE();

    if (!imp_cred_handle) {
        *minor_status = gpp_map_error(EINVAL);
        return GSS_S_NO_CRED;
    }

    impersonator_cred_handle = (struct gpp_cred_handle *)imp_cred_handle;

    if (!output_cred_handle) {
        *minor_status = gpp_map_error(EINVAL);
        return GSS_S_FAILURE;
    }

    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    maj = gpp_cred_handle_init(&min, false, NULL, &out_cred_handle);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    name = (struct gpp_name_handle *)desired_name;
    behavior = gpp_get_behavior();

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = acquire_local(&min, impersonator_cred_handle, name,
                            time_req, desired_mechs, cred_usage, NULL,
                            out_cred_handle, actual_mechs, time_rec);

        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (name && name->local && !name->remote) {
        maj = gpp_local_to_name(&min, name->local, &name->remote);
        if (maj) {
            goto done;
        }
    }

    maj = gpm_acquire_cred(&min,
                           impersonator_cred_handle->remote,
                           name ? name->remote : NULL,
                           time_req,
                           desired_mechs,
                           cred_usage,
                           true,
                           &out_cred_handle->remote,
                           actual_mechs,
                           time_rec);
    if (maj == GSS_S_COMPLETE || behavior == GPP_REMOTE_ONLY) {
        goto done;
    }

    if (behavior == GPP_REMOTE_FIRST) {
        /* So remote failed, but we can fallback to local, try that */
        maj = acquire_local(&min, impersonator_cred_handle, name,
                            time_req, desired_mechs, cred_usage, NULL,
                            out_cred_handle, actual_mechs, time_rec);
    }

done:
    if (maj != GSS_S_COMPLETE &&
        maj != GSS_S_CONTINUE_NEEDED &&
        tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    if (maj == GSS_S_COMPLETE) {
        *output_cred_handle = (gss_cred_id_t)out_cred_handle;
    } else {
        free(out_cred_handle);
    }
    *minor_status = gpp_map_error(min);
    return maj;
}
