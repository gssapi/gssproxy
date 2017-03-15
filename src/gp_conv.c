/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "gp_conv.h"
#include "src/gp_common.h"

void *gp_memdup(void *in, size_t len)
{
    void *out;

    out = malloc(len);
    if (!out) {
        return NULL;
    }

    memcpy(out, in, len);

    return out;
}

int gp_conv_octet_string(size_t length, void *value, octet_string *out)
{
    if (length == 0) {
        out->octet_string_val = NULL;
        out->octet_string_len = 0;
        return 0;
    }

    out->octet_string_val = gp_memdup(value, length);
    if (!out->octet_string_val) {
        return ENOMEM;
    }
    out->octet_string_len = length;
    return 0;
}

int gp_conv_octet_string_alloc(size_t length, void *value,
                               octet_string **out)
{
    octet_string *o;
    int ret;

    o = calloc(1, sizeof(octet_string));
    if (!o) {
        return ENOMEM;
    }

    ret = gp_conv_octet_string(length, value, o);
    if (ret) {
        free(o);
        return ret;
    }

    *out = o;
    return 0;
}

void gp_conv_gssx_to_oid(gssx_OID *in, gss_OID out)
{
    if (in == NULL) {
        out->length = 0;
        out->elements = NULL;
        return;
    }
    out->length = in->octet_string_len;
    out->elements = (void *)in->octet_string_val;
}

int gp_conv_gssx_to_oid_alloc(gssx_OID *in, gss_OID *out)
{
    gss_OID o;

    if (in == NULL || in->octet_string_len == 0) {
        *out = GSS_C_NO_OID;
        return 0;
    }

    o = calloc(1, sizeof(gss_OID_desc));
    if (!o) {
        return ENOMEM;
    }
    o->elements = gp_memdup(in->octet_string_val,
                            in->octet_string_len);
    if (!o->elements) {
        free(o);
        return ENOMEM;
    }
    o->length = in->octet_string_len;

    *out = o;
    return 0;
}

int gp_conv_oid_to_gssx(gss_OID in, gssx_OID *out)
{
    if (in == GSS_C_NO_OID) {
        return gp_conv_octet_string(0, NULL, out);
    }
    return gp_conv_octet_string(in->length, in->elements, out);
}

int gp_conv_oid_to_gssx_alloc(gss_OID in, gssx_OID **out)
{
    if (in == GSS_C_NO_OID) {
        *out = NULL;
        return 0;
    }
    return gp_conv_octet_string_alloc(in->length, in->elements, out);
}

void gp_conv_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out)
{
    out->length = in->octet_string_len;
    out->value = (void *)in->octet_string_val;
}

int gp_conv_gssx_to_buffer_alloc(gssx_buffer *in, gss_buffer_t *out)
{
    gss_buffer_desc *o;

    if (in->octet_string_len == 0) {
        *out = GSS_C_NO_BUFFER;
        return 0;
    }

    o = malloc(sizeof(gss_buffer_desc));
    if (!o) {
        return ENOMEM;
    }

    o->value = gp_memdup(in->octet_string_val,
                         in->octet_string_len);
    if (!o->value) {
        free(o);
        return ENOMEM;
    }
    o->length = in->octet_string_len;

    *out = o;
    return 0;
}

int gp_copy_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out)
{
    gss_buffer_desc empty = GSS_C_EMPTY_BUFFER;

    if (in->octet_string_len == 0) {
        *out = empty;
        return 0;
    }

    out->value = gp_memdup(in->octet_string_val,
                           in->octet_string_len);
    if (!out->value) {
        return ENOMEM;
    }
    out->length = in->octet_string_len;
    return 0;
}

int gp_copy_gssx_to_string_buffer(gssx_buffer *in, gss_buffer_t out)
{
    gss_buffer_desc empty = GSS_C_EMPTY_BUFFER;
    char *str;

    if (in->octet_string_len == 0) {
        *out = empty;
        return 0;
    }

    str = malloc(in->octet_string_len + 1);
    if (!str) {
        return ENOMEM;
    }
    memcpy(str, in->octet_string_val, in->octet_string_len);
    str[in->octet_string_len] = '\0';
    out->length = in->octet_string_len;
    out->value = str;
    return 0;
}

int gp_conv_buffer_to_gssx(gss_buffer_t in, gssx_buffer *out)
{
    return gp_conv_octet_string(in->length, in->value, out);
}

int gp_conv_buffer_to_gssx_alloc(gss_buffer_t in, gssx_buffer **out)
{
    return gp_conv_octet_string_alloc(in->length, in->value, out);
}

void gp_conv_gssx_to_cb(gssx_cb *in, gss_channel_bindings_t out)
{
    out->initiator_addrtype = in->initiator_addrtype;
    gp_conv_gssx_to_buffer(&in->initiator_address, &out->initiator_address);
    out->acceptor_addrtype = in->acceptor_addrtype;
    gp_conv_gssx_to_buffer(&in->acceptor_address, &out->acceptor_address);
    gp_conv_gssx_to_buffer(&in->application_data, &out->application_data);
}

int gp_conv_cb_to_gssx(gss_channel_bindings_t in, gssx_cb *out)
{
    int ret;

    out->initiator_addrtype = in->initiator_addrtype;
    ret = gp_conv_buffer_to_gssx(&in->initiator_address,
                                 &out->initiator_address);
    if (ret) {
        goto done;
    }
    out->acceptor_addrtype = in->acceptor_addrtype;
    ret = gp_conv_buffer_to_gssx(&in->acceptor_address,
                                 &out->acceptor_address);
    if (ret) {
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&in->application_data,
                                 &out->application_data);
    if (ret) {
        goto done;
    }

    ret = 0;

done:
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->initiator_address);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->acceptor_address);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->application_data);
    }
    return ret;
}

int gp_conv_cb_to_gssx_alloc(gss_channel_bindings_t in, gssx_cb **out)
{
    gssx_cb *o;
    int ret;

    o = malloc(sizeof(gssx_cb));
    if (!o) {
        return ENOMEM;
    }

    ret = gp_conv_cb_to_gssx(in, o);
    if (ret) {
        free(o);
        return ENOMEM;
    }

    *out = o;
    return 0;
}

gssx_cred_usage gp_conv_cred_usage_to_gssx(gss_cred_usage_t in)
{
    switch (in) {
    case GSS_C_BOTH:
        return GSSX_C_BOTH;
    case GSS_C_INITIATE:
        return GSSX_C_INITIATE;
    case GSS_C_ACCEPT:
        return GSSX_C_ACCEPT;
    default:
        return 0;
    }
}

gss_cred_usage_t gp_conv_gssx_to_cred_usage(gssx_cred_usage in)
{
    switch (in) {
    case GSSX_C_BOTH:
        return GSS_C_BOTH;
    case GSSX_C_INITIATE:
        return GSS_C_INITIATE;
    case GSSX_C_ACCEPT:
        return GSS_C_ACCEPT;
    default:
        return 0;
    }
}

int gp_conv_err_to_gssx_string(uint32_t status, int type, gss_OID oid,
                               utf8string *ret_str)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t msg_ctx;
    gss_buffer_desc gssbuf;
    char *str, *t;
    int ret = 0;

    msg_ctx = 0;
    str = NULL;
    do {
        ret_maj = gss_display_status(&ret_min,
                                     status, type, oid,
                                     &msg_ctx, &gssbuf);
        if (ret_maj == GSS_S_COMPLETE) {
            if (str) {
                ret = asprintf(&t, "%s, %s", str, (char *)gssbuf.value);
                if (ret == -1) {
                    ret = ENOMEM;
                } else {
                    free(str);
                    str = t;
                }
            } else {
                str = strdup((char *)gssbuf.value);
                if (!str) {
                    ret = ENOMEM;
                }
            }
            gss_release_buffer(&ret_min, &gssbuf);
        } else {
            ret = EINVAL;
        }
        if (ret) {
            goto done;
        }
    } while (msg_ctx);

    ret_str->utf8string_len = strlen(str) + 1;
    ret_str->utf8string_val = str;
    ret = 0;

done:
    if (ret) {
        free(str);
    }
    return ret;
}

uint32_t gp_conv_name_to_gssx(uint32_t *min, gss_name_t in, gssx_name *_out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_buffer_desc name_buffer = GSS_C_EMPTY_BUFFER;
    gss_OID name_type;
    gss_buffer_desc exported_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc exported_composite_name = GSS_C_EMPTY_BUFFER;
    gssx_name out = { .display_name.octet_string_len = 0 };
    int ret;

    ret_maj = gss_display_name(&ret_min, in, &name_buffer, &name_type);
    if (ret_maj) {
        goto done;
    }

    ret = gp_conv_buffer_to_gssx(&name_buffer, &out.display_name);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }
    ret = gp_conv_oid_to_gssx(name_type, &out.name_type);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret_maj = gss_export_name(&ret_min, in, &exported_name);
    if (ret_maj == 0) {
        ret = gp_conv_buffer_to_gssx(&exported_name, &out.exported_name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    } else {
        /* In case the error is GSS_S_NAME_NOT_MN the name was not
         * canonicalized but that is ok we simply do not export the name
         * in this case */
        if (ret_maj != GSS_S_NAME_NOT_MN) {
            goto done;
        }
    }

    ret_maj = gss_export_name_composite(&ret_min, in, &exported_composite_name);
    if (ret_maj == 0) {
        ret = gp_conv_buffer_to_gssx(&exported_composite_name, &out.exported_composite_name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
    } else {
        /* In case the error is GSS_S_NAME_NOT_MN the name was not
         * canonicalized but that is ok we simply do not export the name
         * in this case */
        if (ret_maj != GSS_S_NAME_NOT_MN &&
            ret_maj != GSS_S_UNAVAILABLE) {
            goto done;
        }
    }

    ret_maj = GSS_S_COMPLETE;

    /* out->name_attributes */

done:
    *min = ret_min;
    gss_release_buffer(&ret_min, &name_buffer);
    gss_release_buffer(&ret_min, &exported_name);
    gss_release_buffer(&ret_min, &exported_composite_name);
    if (ret_maj) {
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out.display_name);
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out.name_type);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out.exported_name);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out.exported_composite_name);
    } else {
        *_out = out;
    }
    return ret_maj;
}

uint32_t gp_conv_name_to_gssx_alloc(uint32_t *min,
                                    gss_name_t in, gssx_name **out)
{
    gssx_name *o;
    uint32_t ret_maj;

    o = calloc(1, sizeof(gssx_name));
    if (!o) {
        return ENOMEM;
    }

    ret_maj = gp_conv_name_to_gssx(min, in, o);

    if (ret_maj) {
        free(o);
    } else {
        *out = o;
    }

    return ret_maj;
}

uint32_t gp_conv_gssx_to_name(uint32_t *min, gssx_name *in, gss_name_t *out)
{
    gss_buffer_t input_name = GSS_C_NO_BUFFER;
    gss_OID name_type = GSS_C_NO_OID;
    gss_buffer_desc name_buffer;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;

    if (in->display_name.octet_string_len != 0) {
        /* ok we have a display name.
         * In this case always import and canonicalize it so we can
         * safely export the name using the original form, even if we
         * already have exported_name */
        ret = gp_conv_gssx_to_buffer_alloc(&in->display_name, &input_name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        ret = gp_conv_gssx_to_oid_alloc(&in->name_type, &name_type);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        ret_maj = gss_import_name(&ret_min, input_name, name_type, out);
        if (ret_maj) {
            goto done;
        }
    } else {
        gp_conv_gssx_to_buffer(&in->exported_name, &name_buffer);

        ret_maj = gss_import_name(&ret_min, &name_buffer,
                                  GSS_C_NT_EXPORT_NAME, out);
        if (ret_maj) {
            goto done;
        }
    }

done:
    *min = ret_min;
    gss_release_buffer(&ret_min, input_name);
    free(input_name);
    gss_release_oid(&ret_min, &name_type);
    return ret_maj;
}

int gp_conv_status_to_gssx(uint32_t ret_maj, uint32_t ret_min,
                           gss_OID mech, struct gssx_status *status)
{
    int ret;

    status->major_status = ret_maj;

    if (mech) {
        ret = gp_conv_oid_to_gssx(mech, &status->mech);
        if (ret) {
            goto done;
        }
    }

    status->minor_status = ret_min;

    if (ret_maj) {
        ret = gp_conv_err_to_gssx_string(ret_maj, GSS_C_GSS_CODE, mech,
                                         &status->major_status_string);
        if (ret) {
            goto done;
        }
    }

    if (ret_min) {
        ret = gp_conv_err_to_gssx_string(ret_min, GSS_C_MECH_CODE, mech,
                                         &status->minor_status_string);
        if (ret) {
            goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

int gp_copy_utf8string(utf8string *in, utf8string *out)
{
    out->utf8string_val = gp_memdup(in->utf8string_val,
                                    in->utf8string_len);
    if (!out->utf8string_val) {
        return ENOMEM;
    }
    out->utf8string_len = in->utf8string_len;
    return 0;
}

int gp_copy_gssx_status_alloc(gssx_status *in, gssx_status **out)
{
    gssx_status *o;
    int ret;

    o = calloc(1, sizeof(gssx_status));
    if (!o) {
        return ENOMEM;
    }

    o->major_status = in->major_status;
    o->minor_status = in->minor_status;

    if (in->mech.octet_string_len) {
        ret = gp_conv_octet_string(in->mech.octet_string_len,
                                   in->mech.octet_string_val,
                                   &o->mech);
        if (ret) {
            goto done;
        }
    }

    if (in->major_status_string.utf8string_len) {
        ret = gp_copy_utf8string(&in->major_status_string,
                                 &o->major_status_string);
        if (ret) {
            goto done;
        }
    }

    if (in->minor_status_string.utf8string_len) {
        ret = gp_copy_utf8string(&in->minor_status_string,
                                 &o->minor_status_string);
        if (ret) {
            goto done;
        }
    }

    if (in->server_ctx.octet_string_len) {
        ret = gp_conv_octet_string(in->server_ctx.octet_string_len,
                                   in->server_ctx.octet_string_val,
                                   &o->server_ctx);
        if (ret) {
            goto done;
        }
    }

    *out = o;
    ret = 0;

done:
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_status, (char *)o);
        free(o);
    }
    return ret;
}

int gp_conv_gssx_to_oid_set(gssx_OID_set *in, gss_OID_set *out)
{
    gss_OID_set o;

    if (in->gssx_OID_set_len == 0) {
        *out = GSS_C_NO_OID_SET;
        return 0;
    }

    o = malloc(sizeof(gss_OID_set_desc));
    if (!o) {
        return ENOMEM;
    }

    o->count = in->gssx_OID_set_len;
    o->elements = calloc(o->count, sizeof(gss_OID_desc));
    if (!o->elements) {
        free(o);
        return ENOMEM;
    }

    for (size_t i = 0; i < o->count; i++) {
        o->elements[i].elements =
                        gp_memdup(in->gssx_OID_set_val[i].octet_string_val,
                                  in->gssx_OID_set_val[i].octet_string_len);
        if (!o->elements[i].elements) {
            while (i > 0) {
                i--;
                free(o->elements[i].elements);
            }
            free(o->elements);
            free(o);
            return ENOMEM;
        }
        o->elements[i].length = in->gssx_OID_set_val[i].octet_string_len;
    }

    *out = o;
    return 0;
}

int gp_conv_oid_set_to_gssx(gss_OID_set in, gssx_OID_set *out)
{
    int ret;

    if (in->count == 0) {
        return 0;
    }

    out->gssx_OID_set_len = in->count;
    out->gssx_OID_set_val = calloc(in->count, sizeof(gssx_OID));
    if (!out->gssx_OID_set_val) {
        return ENOMEM;
    }

    for (size_t i = 0; i < in->count; i++) {
        ret = gp_conv_octet_string(in->elements[i].length,
                                   in->elements[i].elements,
                                   &out->gssx_OID_set_val[i]);
        if (ret) {
            while (i > 0) {
                i--;
                free(out->gssx_OID_set_val[i].octet_string_val);
            }
            free(out->gssx_OID_set_val);
            return ENOMEM;
        }
    }

    return 0;
}

int gp_copy_gssx_name(gssx_name *in, gssx_name *out)
{
    int ret;

    ret = gp_conv_octet_string(in->display_name.octet_string_len,
                               in->display_name.octet_string_val,
                               &out->display_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_octet_string(in->name_type.octet_string_len,
                               in->name_type.octet_string_val,
                               &out->name_type);
    if (ret) {
        goto done;
    }
    ret = gp_conv_octet_string(in->exported_name.octet_string_len,
                               in->exported_name.octet_string_val,
                               &out->exported_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_octet_string(in->exported_composite_name.octet_string_len,
                               in->exported_composite_name.octet_string_val,
                               &out->exported_composite_name);
    if (ret) {
        goto done;
    }

done:
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)out);
    }
    return ret;
}

int gp_copy_gssx_name_alloc(gssx_name *in, gssx_name **out)
{
    gssx_name *o;
    int ret;

    o = calloc(1, sizeof(gssx_name));
    if (!o) {
        return ENOMEM;
    }

    ret = gp_copy_gssx_name(in, o);
    if (ret) {
        free(o);
        return ret;
    }
    *out = o;
    return 0;
}
