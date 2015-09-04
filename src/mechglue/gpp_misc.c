/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"

OM_uint32 gssi_mech_invoke(OM_uint32 *minor_status,
                           const gss_OID desired_mech,
                           const gss_OID desired_object,
                           gss_buffer_t value)
{
    enum gpp_behavior behavior;
    OM_uint32 maj, min;

    GSSI_TRACE();

    /* FIXME: implement remote invoke mech, only local for now */
    behavior = gpp_get_behavior();
    if (behavior == GPP_REMOTE_ONLY) {
        return GSS_S_UNAVAILABLE;
    }

    maj = gssspi_mech_invoke(&min, gpp_special_mech(desired_mech),
                             desired_object, value);

    *minor_status = gpp_map_error(min);
    return maj;
}

/* NOTE: This call is currently useful only for the Spnego mech which we
 * never interpose */
#if 0
OM_uint32 gssi_set_neg_mechs(OM_uint32 *minor_status,
                             gss_cred_id_t cred_handle,
                             const gss_OID_set mech_set);
#endif

/* NOTE: I know of no mechanism that uses this yet, although NTLM might */
#if 0
OM_uint32 gssi_complete_auth_token(OM_uint32 *minor_status,
                                   const gss_ctx_id_t context_handle,
                                   gss_buffer_t input_message_buffer);
#endif

OM_uint32 gssi_localname(OM_uint32 *minor_status, const gss_name_t name,
                         gss_OID mech_type, gss_buffer_t localname)
{
    struct gpp_name_handle *gpname;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* FIXME: implement remote localname lookup ? Only local for now */
    gpname = (struct gpp_name_handle *)name;
    if (gpname->remote && !gpname->local) {
        maj = gpp_name_to_local(&min, gpname->remote,
                                mech_type, &gpname->local);
        if (maj) {
            goto done;
        }
    }

    maj = gss_localname(&min, gpname->local,
                        gpp_special_mech(mech_type),
                        localname);

done:
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_authorize_localname(OM_uint32 *minor_status,
                                   const gss_name_t name,
                                   gss_buffer_t local_user,
                                   gss_OID local_nametype)
{
    struct gpp_name_handle *gpname;
    gss_name_t username = GSS_C_NO_NAME;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* FIXME: implement remote localname lookup ? Only local for now */
    gpname = (struct gpp_name_handle *)name;
    if (gpname->remote && !gpname->local) {
        maj = gpp_name_to_local(&min, gpname->remote,
                                gpname->mech_type, &gpname->local);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

    maj = gss_import_name(&min, local_user, local_nametype, &username);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    maj = gss_authorize_localname(&min, gpname->local, username);

done:
    *minor_status = gpp_map_error(min);
    (void)gss_release_name(&min, &username);
    return maj;
}

OM_uint32 gssi_map_name_to_any(OM_uint32 *minor_status, gss_name_t name,
                               int authenticated, gss_buffer_t type_id,
                               gss_any_t *output)
{
    struct gpp_name_handle *gpname;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* FIXME: implement remote localname lookup ? Only local for now */
    gpname = (struct gpp_name_handle *)name;
    if (gpname->remote && !gpname->local) {
        maj = gpp_name_to_local(&min, gpname->remote,
                                gpname->mech_type, &gpname->local);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

    maj = gss_map_name_to_any(&min, gpname->local,
                              authenticated, type_id, output);

done:
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_release_any_name_mapping(OM_uint32 *minor_status,
                                        gss_name_t name,
                                        gss_buffer_t type_id,
                                        gss_any_t *input)
{
    struct gpp_name_handle *gpname;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (name == GSS_C_NO_NAME) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* FIXME: implement remote localname lookup ? Only local for now */
    gpname = (struct gpp_name_handle *)name;
    if (!gpname->local) {
        return GSS_S_UNAVAILABLE;
    }

    maj = gss_release_any_name_mapping(&min, gpname->local, type_id, input);

    *minor_status = gpp_map_error(min);
    return maj;

}
