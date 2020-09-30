/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"

static int gpm_name_oid_to_static(gss_OID name_type, gss_OID *name_static)
{
#define ret_static(b) \
    if (gss_oid_equal(name_type, b)) { \
        *name_static = b; \
        return 0; \
    }
    ret_static(GSS_C_NT_USER_NAME);
    ret_static(GSS_C_NT_MACHINE_UID_NAME);
    ret_static(GSS_C_NT_STRING_UID_NAME);
    ret_static(GSS_C_NT_HOSTBASED_SERVICE_X);
    ret_static(GSS_C_NT_HOSTBASED_SERVICE);
    ret_static(GSS_C_NT_ANONYMOUS);
    ret_static(GSS_C_NT_EXPORT_NAME);
    ret_static(GSS_C_NT_COMPOSITE_EXPORT);
    ret_static(GSS_KRB5_NT_PRINCIPAL_NAME);
    ret_static(gss_nt_krb5_name);
    return ENOENT;
}

OM_uint32 gpm_display_name(OM_uint32 *minor_status,
                           gssx_name *in_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type)
{
    gss_buffer_desc input_name_buffer = GSS_C_EMPTY_BUFFER;
    gssx_name *output_name = NULL;
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t discard;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!in_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (!output_name_buffer) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (in_name->display_name.octet_string_len == 0) {
        if (in_name->exported_name.octet_string_len == 0) {
            return GSS_S_BAD_NAME;
        }

        gp_conv_gssx_to_buffer(&in_name->exported_name, &input_name_buffer);

        ret_maj = gpm_import_name(&ret_min, &input_name_buffer,
                                  GSS_C_NT_EXPORT_NAME, &output_name);
        if (ret_maj) {
            goto done;
        }

        /* steal display_name and name_type */
        in_name->display_name = output_name->display_name;
        output_name->display_name.octet_string_len = 0;
        output_name->display_name.octet_string_val = NULL;
        in_name->name_type = output_name->name_type;
        output_name->name_type.octet_string_len = 0;
        output_name->name_type.octet_string_val = NULL;
    }

    ret = gp_copy_gssx_to_string_buffer(&in_name->display_name,
                                        output_name_buffer);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    if (output_name_type) {
        gss_OID_desc oid;
        gp_conv_gssx_to_oid(&in_name->name_type, &oid);
        ret = gpm_name_oid_to_static(&oid, output_name_type);
        if (ret) {
            gss_release_buffer(&discard, output_name_buffer);
            ret_min = ret;
            ret_maj = GSS_S_FAILURE;
            goto done;
        }
    }

    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    if (output_name) {
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)output_name);
        free(output_name);
    }
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_import_name(OM_uint32 *minor_status,
                          gss_buffer_t input_name_buffer,
                          gss_OID input_name_type,
                          gssx_name **output_name)
{
    gssx_name *name;
    uint32_t maj, min;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name_buffer || !input_name_type) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (!output_name) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    /* ignore call_ctx for now */

    maj = GSS_S_FAILURE;

    name = calloc(1, sizeof(gssx_name));
    if (!name) {
        ret = ENOMEM;
        goto done;
    }

    ret = gp_conv_buffer_to_gssx(input_name_buffer, &name->display_name);
    if (ret) {
        goto done;
    }

    ret = gp_conv_oid_to_gssx(input_name_type, &name->name_type);
    if (ret) {
        goto done;
    }

    maj = GSS_S_COMPLETE;

done:
    *minor_status = ret;
    if (maj == GSS_S_COMPLETE) {
        *output_name = name;
    } else {
        (void)gpm_release_name(&min, &name);
    }
    return maj;
}

OM_uint32 gpm_export_name(OM_uint32 *minor_status,
                          gssx_name *input_name,
                          gss_buffer_t exported_name)
{
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (input_name->exported_name.octet_string_len == 0) {
        return GSS_S_NAME_NOT_MN;
    }

    ret = gp_copy_gssx_to_buffer(&input_name->exported_name, exported_name);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_export_name_composite(OM_uint32 *minor_status,
                                    gssx_name *input_name,
                                    gss_buffer_t exported_composite_name)
{
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (input_name->exported_composite_name.octet_string_len == 0) {
        return GSS_S_NAME_NOT_MN;
    }

    ret = gp_copy_gssx_to_buffer(&input_name->exported_composite_name,
                                 exported_composite_name);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_duplicate_name(OM_uint32 *minor_status,
                             gssx_name *input_name,
                             gssx_name **dest_name)
{
    int ret;

    ret = gp_copy_gssx_name_alloc(input_name, dest_name);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

static OM_uint32 gpm_int_canonicalize_name(OM_uint32 *minor_status,
                                           gssx_name *input_name,
                                           const gss_OID mech_type,
                                           const char *special_query,
                                           void **output_name)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_import_and_canon_name *arg = &uarg.import_and_canon_name;
    gssx_res_import_and_canon_name *res = &ures.import_and_canon_name;
    uint32_t ret_maj;
    uint32_t ret_min;
    struct gssx_option *val = NULL;
    gssx_buffer *name = NULL;
    bool localname = false;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (!output_name) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    if (special_query && strcmp(special_query, LOCALNAME_OPTION) == 0) {
        localname = true;
    }

    memset(arg, 0, sizeof(gssx_arg_import_and_canon_name));
    memset(res, 0, sizeof(gssx_res_import_and_canon_name));

    /* ignore call_ctx for now */

    ret = gp_copy_gssx_name(input_name, &arg->input_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_oid_to_gssx(mech_type, &arg->mech);
    if (ret) {
        goto done;
    }

    if (localname) {
        ret = gp_add_option(&arg->options.options_val,
                            &arg->options.options_len,
                            LOCALNAME_OPTION,
                            sizeof(LOCALNAME_OPTION),
                            NULL, 0);
        if (ret) {
            goto done;
        }
    }

    /* execute proxy request */
    ret = gpm_make_call(GSSX_IMPORT_AND_CANON_NAME, &uarg, &ures);
    if (ret) {
        goto done;
    }

    ret_min = res->status.minor_status;
    ret_maj = res->status.major_status;
    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret = 0;
        goto done;
    }

    if (!localname) {
        /* steal output_name */
        *(gssx_name **)output_name = res->output_name;
        res->output_name = NULL;
        ret = 0;
        goto done;
    }

    gp_options_find(val, res->options,
                    LOCALNAME_OPTION, sizeof(LOCALNAME_OPTION));
    if (!val) {
        ret = ENOTSUP;
        goto done;
    }

    name = malloc(sizeof(gssx_buffer));
    if (!name) {
        ret = ENOMEM;
        goto done;
    }

    /* steal value */
    *name = val->value;
    memset(&val->value, 0, sizeof(gssx_buffer));
    *(gssx_buffer **)output_name = name;

    ret = 0;

done:
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
    }
    gpm_free_xdrs(GSSX_IMPORT_AND_CANON_NAME, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_canonicalize_name(OM_uint32 *minor_status,
                                gssx_name *input_name,
                                const gss_OID mech_type,
                                gssx_name **output_name)
{
    return gpm_int_canonicalize_name(minor_status, input_name, mech_type,
                                     NULL, (void **)output_name);
}

OM_uint32 gpm_inquire_name(OM_uint32 *minor_status,
                           gssx_name *name,
                           int *name_is_MN,
                           gss_OID *MN_mech,
                           gss_buffer_set_t *attrs)
{
    gss_buffer_set_t xattrs = GSS_C_NO_BUFFER_SET;
    int ret;

    *minor_status = 0;

    if (name->exported_name.octet_string_len != 0) {
        if (name_is_MN != NULL) {
            *name_is_MN = 1;
        }
    }

    if (MN_mech != NULL) {
        gss_OID_desc oid;
        gp_conv_gssx_to_oid(&name->name_type, &oid);
        ret = gpm_name_oid_to_static(&oid, MN_mech);
        if (ret) {
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
    }

    if (name->name_attributes.name_attributes_len != 0) {
        xattrs = calloc(1, sizeof(gss_buffer_set_desc));
        if (!xattrs) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        xattrs->count = name->name_attributes.name_attributes_len;
        xattrs->elements = calloc(xattrs->count, sizeof(gss_buffer_desc));
        if (!xattrs->elements) {
            free(xattrs);
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        for (unsigned i = 0; i < xattrs->count; i++) {
            ret = gp_copy_gssx_to_buffer(
                        &name->name_attributes.name_attributes_val[i].attr,
                        &xattrs->elements[i]);
            if (ret) {
                for (; i > 0; i--) {
                    free(xattrs->elements[i-1].value);
                }
                free(xattrs->elements);
                free(xattrs);
                *minor_status = ENOMEM;
                return GSS_S_FAILURE;
            }
        }
    }
    *attrs = xattrs;

    return GSS_S_COMPLETE;
}

OM_uint32 gpm_release_name(OM_uint32 *minor_status,
                           gssx_name **input_name)
{
    *minor_status = 0;

    if (*input_name != NULL) {
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)(*input_name));
        free(*input_name);
        *input_name = NULL;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_compare_name(OM_uint32 *minor_status,
                           gssx_name *name1,
                           gssx_name *name2,
                           int *name_equal)
{
    gss_buffer_desc buf1 = {0};
    gss_buffer_desc buf2 = {0};
    gss_OID type1 = GSS_C_NO_OID;
    gss_OID type2 = GSS_C_NO_OID;
    uint32_t ret_maj;
    uint32_t ret_min;
    int c;

    *name_equal = 0;

    ret_maj = gpm_display_name(&ret_min, name1, &buf1, &type1);
    if (ret_maj != GSS_S_COMPLETE) {
        goto done;
    }

    ret_maj = gpm_display_name(&ret_min, name2, &buf2, &type2);
    if (ret_maj != GSS_S_COMPLETE) {
        goto done;
    }

    c = buf1.length - buf2.length;
    if (c == 0) {
        c = memcmp(buf1.value, buf2.value, buf1.length);
        if (c == 0) {
            c = gss_oid_equal(type1, type2);
        }
    }

    if (c != 0) {
        *name_equal = 1;
    }

    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    *minor_status = ret_min;
    gss_release_buffer(&ret_min, &buf1);
    gss_release_buffer(&ret_min, &buf2);
    gss_release_oid(&ret_min, &type1);
    gss_release_oid(&ret_min, &type2);
    return ret_maj;
}

OM_uint32 gpm_localname(OM_uint32 *minor_status,
                        gssx_name *input_name,
                        const gss_OID mech_type,
                        gss_buffer_t localname)
{
    gssx_buffer *output = NULL;
    uint32_t maj;

    maj = gpm_int_canonicalize_name(minor_status, input_name, mech_type,
                                    LOCALNAME_OPTION, (void **)&output);
    if (maj != GSS_S_COMPLETE) return maj;

    /* steal result */
    gp_conv_gssx_to_buffer(output, localname);

    free(output);
    return GSS_S_COMPLETE;
}
