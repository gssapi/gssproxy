/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"

OM_uint32 gssi_display_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            gss_buffer_t output_name_buffer,
                            gss_OID *output_name_type)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    output_name_buffer->length = 0;
    output_name_buffer->value = NULL;
    if (output_name_type)
        *output_name_type = GSS_C_NO_OID;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_display_name(&min,
                               name->local,
                               output_name_buffer,
                               output_name_type);
    } else {
        maj = gpm_display_name(&min,
                               name->remote,
                               output_name_buffer,
                               output_name_type);
    }

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_display_name_ext(OM_uint32 *minor_status,
                                gss_name_t input_name,
                                gss_OID display_as_name_type,
                                gss_buffer_t display_name)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_display_name_ext(&min, name->local,
                                   display_as_name_type,
                                   display_name);
    } else {
        /* FIXME: Implement remote function ?
         * Or export/import via local mechanism ? */
        maj = GSS_S_UNAVAILABLE;
    }

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_import_name(OM_uint32 *minor_status,
                           gss_buffer_t input_name_buffer,
                           gss_OID input_name_type,
                           gss_name_t *output_name)
{
    GSSI_TRACE();
    return GSS_S_UNAVAILABLE;
}

OM_uint32 gssi_import_name_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t input_name_buffer,
                                   gss_OID input_name_type,
                                   gss_name_t *output_name)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    if (mech_type == GSS_C_NO_OID) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    name = calloc(1, sizeof(struct gpp_name_handle));
    if (!name) {
        *minor_status = gpp_map_error(ENOMEM);
        return GSS_S_FAILURE;
    }

    maj = gpp_copy_oid(&min, mech_type, &name->mech_type);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    /* Always use remote name by default, otherwise canonicalization
     * will loose information about the original name, for example
     * it will convert names of the special type GSS_C_NT_STRING_UID_NAME
     * or GSS_NT_MACHINE_UID_NAME in a non reversible way and the proxy
     * will not be able to use them as intended (for impersonation by
     * trusted services) */
    maj = gpm_import_name(&min,
                          input_name_buffer,
                          input_name_type,
                          &name->remote);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

done:
    *minor_status = gpp_map_error(min);
    if (maj != GSS_S_COMPLETE) {
        (void)gss_release_oid(&min, &name->mech_type);
        (void)gpm_release_name(&min, &name->remote);
        free(name);
    } else {
        *output_name = (gss_name_t)name;
    }
    return maj;
}

/* OM_uint32 gssi_export_name(OM_uint32 *minor_status,
                           const gss_name_t input_name,
                           gss_buffer_t exported_name) */
#if 0
/* disabled until better understood */
OM_uint32 gssi_export_name_composite(OM_uint32 *minor_status,
                                     const gss_name_t input_name,
                                     gss_buffer_t exported_composite_name)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_export_name_composite(&min, name->local,
                                        exported_composite_name);
    } else {
        maj = gpm_export_name_composite(&min, name->remote,
                                        exported_composite_name);
    }

    *minor_status = gpp_map_error(min);
    return maj;
}
#endif

OM_uint32 gssi_duplicate_name(OM_uint32 *minor_status,
                              const gss_name_t input_name,
                              gss_name_t *dest_name)
{
    struct gpp_name_handle *in_name;
    struct gpp_name_handle *out_name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    in_name = (struct gpp_name_handle *)input_name;
    if (!in_name->local && !in_name->remote) {
        return GSS_S_BAD_NAME;
    }

    out_name = calloc(1, sizeof(struct gpp_name_handle));
    if (!out_name) {
        *minor_status = gpp_map_error(ENOMEM);
        return GSS_S_FAILURE;
    }

    if (in_name->mech_type) {
        maj = gpp_copy_oid(&min, in_name->mech_type, &out_name->mech_type);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

    if (in_name->remote) {
        maj = gpm_duplicate_name(&min,
                                 in_name->remote,
                                 &out_name->remote);
    } else {
        maj = gss_duplicate_name(&min,
                                 in_name->local,
                                 &out_name->local);
    }

done:
    *minor_status = gpp_map_error(min);
    if (maj != GSS_S_COMPLETE) {
        (void)gss_release_oid(&min, &out_name->mech_type);
        free(out_name);
    } else {
        *dest_name = (gss_name_t)out_name;
    }
    return maj;
}

OM_uint32 gssi_inquire_name(OM_uint32 *minor_status,
                            gss_name_t input_name,
                            int *name_is_NM,
                            gss_OID *NM_mech,
                            gss_buffer_set_t *attrs)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_inquire_name(&min,
                               name->local,
                               name_is_NM,
                               NM_mech,
                               attrs);
    } else {
        maj = gpm_inquire_name(&min,
                               name->remote,
                               name_is_NM,
                               NM_mech,
                               attrs);
    }

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_release_name(OM_uint32 *minor_status,
                            gss_name_t *input_name)
{
    struct gpp_name_handle *name;
    uint32_t rmaj, rmin = 0;
    OM_uint32 maj = 0, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)*input_name;
    if (!name || (!name->local && !name->remote)) {
        return GSS_S_BAD_NAME;
    }

    rmaj = gpm_release_name(&rmin, &name->remote);

    if (name->local) {
        maj = gss_release_name(&min, &name->local);
    }

    free(name);
    *input_name = GSS_C_NO_NAME;

    if (rmaj && !maj) {
        maj = rmaj;
        min = rmin;
    }
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_compare_name(OM_uint32 *minor_status,
                            gss_name_t name1,
                            gss_name_t name2,
                            int *name_equal)
{
    struct gpp_name_handle *gpname1;
    struct gpp_name_handle *gpname2;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    gpname1 = (struct gpp_name_handle *)name1;
    gpname2 = (struct gpp_name_handle *)name2;

    if (gpname1->local || gpname2->local) {
        if (!gpname1->local) {
            if (!gpname1->remote){
                return GSS_S_CALL_INACCESSIBLE_READ;
            }
            maj = gpp_name_to_local(&min, gpname1->remote,
                                    gpname1->mech_type, &gpname1->local);
            if (maj != GSS_S_COMPLETE) {
                goto done;
            }
        }
        if (!gpname2->local) {
            if (!gpname2->remote){
                return GSS_S_CALL_INACCESSIBLE_READ;
            }
            maj = gpp_name_to_local(&min, gpname2->remote,
                                    gpname2->mech_type, &gpname2->local);
            if (maj != GSS_S_COMPLETE) {
                goto done;
            }
        }

        maj = gss_compare_name(&min,
                               gpname1->local, gpname2->local, name_equal);
        goto done;
    }

    if (!gpname1->remote && !gpname2->remote) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    maj = gpm_compare_name(&min, gpname1->remote, gpname2->remote, name_equal);

done:
    *minor_status = gpp_map_error(min);
    return maj;

}

OM_uint32 gssi_get_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  gss_buffer_t attr,
                                  int *authenticated,
                                  int *complete,
                                  gss_buffer_t value,
                                  gss_buffer_t display_value,
                                  int *more)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_get_name_attribute(&min, name->local, attr,
                                     authenticated, complete,
                                     value, display_value, more);
    } else {
        /* FIXME: Implement retrieving remote attributes! */
        maj = GSS_S_UNAVAILABLE;
    }

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_set_name_attribute(OM_uint32 *minor_status,
                                  gss_name_t input_name,
                                  int complete,
                                  gss_buffer_t attr,
                                  gss_buffer_t value)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_set_name_attribute(&min, name->local,
                                     complete, attr, value);
    } else {
        /* FIXME: Implement retrieving remote attributes! */
        maj = GSS_S_UNAVAILABLE;
    }

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_delete_name_attribute(OM_uint32 *minor_status,
                                     gss_name_t input_name,
                                     gss_buffer_t attr)
{
    struct gpp_name_handle *name;
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    name = (struct gpp_name_handle *)input_name;
    if (!name->local && !name->remote) {
        return GSS_S_BAD_NAME;
    }

    if (name->local) {
        maj = gss_delete_name_attribute(&min, name->local, attr);
    } else {
        /* FIXME: Implement retrieving remote attributes! */
        maj = GSS_S_UNAVAILABLE;
    }

    *minor_status = gpp_map_error(min);
    return maj;
}
