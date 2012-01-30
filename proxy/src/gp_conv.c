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

#include "config.h"
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "gp_conv.h"

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
    out->length = in->octet_string_len;
    out->elements = (void *)in->octet_string_val;
}

int gp_conv_gssx_to_oid_alloc(gssx_OID *in, gss_OID *out)
{
    gss_OID o;

    o = calloc(1, sizeof(gss_OID));
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
    return 0;
}

int gp_conv_oid_to_gssx(gss_OID in, gssx_OID *out)
{
    return gp_conv_octet_string(in->length, in->elements, out);
}

int gp_conv_oid_to_gssx_alloc(gss_OID in, gssx_OID **out)
{
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

int gp_conv_buffer_to_gssx(gss_buffer_t in, gssx_buffer *out)
{
    return gp_conv_octet_string(in->length, in->value, out);
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
    int ret;

    msg_ctx = 0;
    str = NULL;
    do {
        ret_maj = gss_display_status(&ret_min,
                                     status, type, oid,
                                     &msg_ctx, &gssbuf);
        if (ret_maj == 0) {
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
        }
        if (ret_maj) {
            ret = EINVAL;
            goto done;
        }
    } while (msg_ctx);

    ret_str->utf8string_len = strlen(str + 1);
    ret_str->utf8string_val = str;
    ret = 0;

done:
    if (ret) {
        free(str);
    }
    return ret;
}

int gp_conv_name_to_gssx(gss_name_t in, gssx_name *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_buffer_desc name_buffer;
    gss_OID name_type;
    gss_buffer_desc exported_name;
    int ret;

    ret_maj = gss_display_name(&ret_min, in, &name_buffer, &name_type);
    if (ret_maj) {
        return -1;
    }

    out->display_name = calloc(1, sizeof(gssx_buffer));
    if (!out->display_name) {
        ret = ENOMEM;
        goto done;
    }

    ret = gp_conv_buffer_to_gssx(&name_buffer, out->display_name);
    if (ret) {
        goto done;
    }
    ret = gp_conv_oid_to_gssx(name_type, &out->name_type);
    if (ret) {
        goto done;
    }

    ret_maj = gss_export_name(&ret_min, in, &exported_name);
    if (ret_maj) {
        ret = -1;
        goto done;
    }

    ret = gp_conv_buffer_to_gssx(&exported_name, &out->exported_name);
    if (ret) {
        goto done;
    }

    /* out->exported_composite_name */
    /* out->name_attributes */

done:
    gss_release_buffer(&ret_min, &name_buffer);
    gss_release_buffer(&ret_min, &exported_name);
    if (ret) {
        if (out->display_name) {
            xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)out->display_name);
            free(out->display_name);
        }
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->name_type);
        xdr_free((xdrproc_t)xdr_gssx_buffer, (char *)&out->exported_name);
    }
    return ret;
}

int gp_conv_gssx_to_name(gssx_name *in, gss_name_t *out)
{
    uint32_t ret_min;
    gss_buffer_desc name_buffer;
    gss_OID_desc name_type;

    gp_conv_gssx_to_oid(&in->name_type, &name_type);

    gp_conv_gssx_to_buffer(&in->exported_name, &name_buffer);

    return gss_import_name(&ret_min, &name_buffer, &name_type, out);
}

int gp_conv_ctx_id_to_gssx(gss_ctx_id_t *in, gssx_ctx *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_name_t targ_name = GSS_C_NO_NAME;
    gss_buffer_desc export_buffer = GSS_C_EMPTY_BUFFER;
    uint32_t lifetime_rec;
    gss_OID mech_type;
    uint32_t ctx_flags;
    int is_locally_initiated;
    int is_open;
    int ret;

    /* TODO: For mechs that need multiple roundtrips to complete */
    /* out->state; */

    /* we do not need the client to release anything nutil we handle state */
    out->needs_release = false;

    ret_maj = gss_inquire_context(&ret_min, *in, &src_name, &targ_name,
                                  &lifetime_rec, &mech_type, &ctx_flags,
                                  &is_locally_initiated, &is_open);
    if (ret_maj) {
        ret = EINVAL;
        goto done;
    }

    ret = gp_conv_oid_to_gssx(mech_type, &out->mech);
    if (ret) {
        goto done;
    }

    ret = gp_conv_name_to_gssx(src_name, &out->src_name);
    if (ret) {
        goto done;
    }

    ret = gp_conv_name_to_gssx(targ_name, &out->targ_name);
    if (ret) {
        goto done;
    }

    out->lifetime = lifetime_rec;

    out->ctx_flags = ctx_flags;

    if (is_locally_initiated) {
        out->locally_initiated = true;
    }

    if (is_open) {
        out->open = true;
    }

    /* note: once converted the original context token is not usable anymore,
     * so this must be the last call to use it */
    out->exported_context_token = calloc(1, sizeof(octet_string));
    if (!out->exported_context_token) {
        ret = ENOMEM;
        goto done;
    }
    ret_maj = gss_export_sec_context(&ret_min, in, &export_buffer);
    if (ret_maj) {
        ret = EINVAL;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&export_buffer, out->exported_context_token);
    if (ret) {
        goto done;
    }

    /* Leave this empty, used only on the way in for init_sec_context */
    /* out->gssx_option */

done:
    gss_release_name(&ret_min, &src_name);
    gss_release_name(&ret_min, &targ_name);
    gss_release_buffer(&ret_min, &export_buffer);
    if (ret) {
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->mech);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->src_name);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->targ_name);
    }
    return ret;
}

int gp_conv_status_to_gssx(struct gssx_call_ctx *call_ctx,
                           uint32_t ret_maj, uint32_t ret_min,
                           gss_OID mech, struct gssx_status *status)
{
    int ret;

    status->major_status = ret_maj;

    ret = gp_conv_oid_to_gssx(mech, &status->mech);
    if (ret) {
        goto done;
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

