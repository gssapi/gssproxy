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

OM_uint32 gpm_display_name(OM_uint32 *minor_status,
                           gss_name_t input_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type)
{
    gss_buffer_desc input_name_buffer = GSS_C_EMPTY_BUFFER;
    gssx_name *output_name = NULL;
    gss_name_t tmp;
    gssx_name *name;
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t discard;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (!output_name_buffer) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    name = (gssx_name *)input_name;

    if (name->display_name.octet_string_len == 0) {
        if (name->exported_name.octet_string_len == 0) {
            return GSS_S_BAD_NAME;
        }

        gp_conv_gssx_to_buffer(&name->exported_name, &input_name_buffer);
        tmp = (gss_name_t)output_name;

        ret_maj = gpm_import_name(&ret_min, &input_name_buffer,
                                  GSS_C_NT_EXPORT_NAME, &tmp);
        if (ret_maj) {
            goto done;
        }

        /* steal display_name and name_type */
        name->display_name = output_name->display_name;
        output_name->display_name.octet_string_len = 0;
        output_name->display_name.octet_string_val = NULL;
        name->name_type = output_name->name_type;
        output_name->name_type.octet_string_len = 0;
        output_name->name_type.octet_string_val = NULL;
    }

    ret = gp_copy_gssx_to_buffer(&name->display_name, output_name_buffer);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    if (output_name_type) {
        ret = gp_conv_gssx_to_oid_alloc(&name->name_type, output_name_type);
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
                          gss_name_t *output_name)
{
    gssx_name *name;
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

    name = calloc(1, sizeof(gssx_name));
    if (!name) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    ret = gp_conv_buffer_to_gssx(input_name_buffer, &name->display_name);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    ret = gp_conv_oid_to_gssx(input_name_type, &name->name_type);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }

    *output_name = (gss_name_t)name;
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_export_name(OM_uint32 *minor_status,
                          const gss_name_t input_name,
                          gss_buffer_t exported_name)
{
    gssx_name *name;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    name = (gssx_name *)input_name;

    if (name->exported_name.octet_string_len == 0) {
        return GSS_S_NAME_NOT_MN;
    }

    ret = gp_copy_gssx_to_buffer(&name->exported_name, exported_name);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_duplicate_name(OM_uint32 *minor_status,
                             const gss_name_t input_name,
                             gss_name_t *dest_name)
{
    gssx_name *name;
    gssx_name *namecopy;
    int ret;

    name = (gssx_name *)input_name;

    ret = gp_copy_gssx_name_alloc(name, &namecopy);
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }
    *dest_name = (gss_name_t)namecopy;
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_canonicalize_name(OM_uint32 *minor_status,
                                const gss_name_t input_name,
                                const gss_OID mech_type,
                                gss_name_t *output_name)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_import_and_canon_name *arg = &uarg.import_and_canon_name;
    gssx_res_import_and_canon_name *res = &ures.import_and_canon_name;
    uint32_t ret_maj;
    uint32_t ret_min;
    gssx_name *name;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    *minor_status = 0;

    if (!input_name || !mech_type) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (!output_name) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    name = (gssx_name *)input_name;

    memset(arg, 0, sizeof(gssx_arg_import_and_canon_name));
    memset(res, 0, sizeof(gssx_res_import_and_canon_name));

    /* ignore call_ctx for now */

    ret = gp_copy_gssx_name(name, &arg->input_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_oid_to_gssx(mech_type, &arg->mech);
    if (ret) {
        goto done;
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

    /* steal output_name */
    *output_name = (gss_name_t)res->output_name;
    res->output_name = NULL;

done:
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
    }
    gpm_free_xdrs(GSSX_IMPORT_AND_CANON_NAME, &uarg, &ures);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_inquire_name(OM_uint32 *minor_status,
                           gss_name_t name,
                           int *name_is_MN,
                           gss_OID *MN_mech,
                           gss_buffer_set_t *attrs)
{
    gss_buffer_set_t xattrs = GSS_C_NO_BUFFER_SET;
    gssx_name *xname;
    uint32_t i;
    int ret;

    *minor_status = 0;
    xname = (gssx_name *)name;

    if (xname->exported_name.octet_string_len != 0) {
        if (name_is_MN != NULL) {
            *name_is_MN = 1;
        }
    }

    if (MN_mech != NULL) {
        ret = gp_conv_gssx_to_oid_alloc(&xname->name_type, MN_mech);
        if (ret) {
            *minor_status = ret;
            return GSS_S_FAILURE;
        }
    }

    if (xname->name_attributes.name_attributes_len != 0) {
        xattrs = calloc(1, sizeof(gss_buffer_set_desc));
        if (!xattrs) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        xattrs->count = xname->name_attributes.name_attributes_len;
        xattrs->elements = calloc(xattrs->count, sizeof(gss_buffer_desc));
        if (!xattrs->elements) {
            free(xattrs);
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        for (i = 0; i < xattrs->count; i++) {
            ret = gp_copy_gssx_to_buffer(
                        &xname->name_attributes.name_attributes_val[i].attr,
                        &xattrs->elements[i]);
            if (ret) {
                for (--i; i >= 0; i--) {
                    free(xattrs->elements[i].value);
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

