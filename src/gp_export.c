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
#include "gp_export.h"
#include "gp_debug.h"

/* FIXME: F I X M E
 *
 * FFFFF  I  X    X  M    M  EEEEE
 * F      I   X  X   MM  MM  E
 * FFF    I    XX    M MM M  EEE
 * F      I   X  X   M    M  E
 * F      I  X    X  M    M  EEEEE
 *
 * Credential functions should either be implemented with gss_export_cred()
 * or, lacking those calls in the gssapi implementation, by keeping state
 * in a table/list and returning a token.
 * In both cases the content should be encrypted.
 *
 * Temporarily we simply return straight out the gss_cred_id_t pointer as
 * a handle.
 *
 * THIS IS ONLY FOR THE PROTOTYPE
 *
 * *MUST* BE FIXED BEFORE ANY OFFICIAL RELEASE.
 */

uint32_t gp_export_gssx_cred(uint32_t *min,
                             gss_cred_id_t *in, gssx_cred *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t name = NULL;
    uint32_t lifetime;
    gss_cred_usage_t cred_usage;
    gss_OID_set mechanisms = NULL;
    uint32_t initiator_lifetime;
    uint32_t acceptor_lifetime;
    struct gssx_cred_element *el;
    int ret;
    int i, j;

    ret_maj = gss_inquire_cred(&ret_min, *in,
                               &name, &lifetime, &cred_usage, &mechanisms);
    if (ret_maj) {
        goto done;
    }

    ret_maj = gp_conv_name_to_gssx(&ret_min, name, &out->desired_name);
    if (ret_maj) {
        goto done;
    }
    gss_release_name(&ret_min, &name);
    name = NULL;

    out->elements.elements_len = mechanisms->count;
    out->elements.elements_val = calloc(out->elements.elements_len,
                                        sizeof(gssx_cred_element));
    if (!out->elements.elements_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    for (i = 0, j = 0; i < mechanisms->count; i++, j++) {

        el = &out->elements.elements_val[j];

        ret_maj = gss_inquire_cred_by_mech(&ret_min, *in,
                                           &mechanisms->elements[i],
                                           &name,
                                           &initiator_lifetime,
                                           &acceptor_lifetime,
                                           &cred_usage);
        if (ret_maj) {
            gp_log_failure(&mechanisms->elements[i], ret_maj, ret_min);

            /* temporarily skip any offender */
            out->elements.elements_len--;
            j--;
            continue;
#if 0
            ret = EINVAL;
            goto done;
#endif
        }

        ret_maj = gp_conv_name_to_gssx(&ret_min, name, &el->MN);
        if (ret_maj) {
            goto done;
        }
        gss_release_name(&ret_min, &name);
        name = NULL;

        ret = gp_conv_oid_to_gssx(&mechanisms->elements[i], &el->mech);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        el->cred_usage = gp_conv_gssx_to_cred_usage(cred_usage);

        el->initiator_time_rec = initiator_lifetime;
        el->acceptor_time_rec = acceptor_lifetime;
    }

    ret = gp_conv_octet_string(sizeof(gss_cred_id_t), in,
                               &out->cred_handle_reference);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }
    out->needs_release = true;

    /* we take over control of the credentials from here on */
    /* when we will have gss_export_cred() we will actually free
     * them immediately instead */
    *in = NULL;
    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    *min = ret_min;
    gss_release_name(&ret_min, &name);
    gss_release_oid_set(&ret_min, &mechanisms);
    return ret_maj;
}

int gp_import_gssx_cred(octet_string *in, gss_cred_id_t *out)
{
    if (in) {
        memcpy(out, in->octet_string_val, sizeof(gss_cred_id_t));
    } else {
        *out = NULL;
    }
    return 0;
}

int gp_find_cred(gssx_cred *cred, gss_cred_id_t *out)
{
    return gp_import_gssx_cred(&cred->cred_handle_reference, out);
}


/* Exported Contexts */

#define EXP_CTX_TYPE_OPTION "exported_contex_type"
#define LINUX_LUCID_V1      "linux_lucid_v1"

enum exp_ctx_types {
    EXP_CTX_DEFAULT = 0,
    EXP_CTX_LINUX_LUCID_V1 = 1,
};

int gp_get_exported_context_type(struct gssx_call_ctx *ctx)
{

    struct gssx_option *val;
    int i;

    for (i = 0; i < ctx->options.options_len; i++) {
        val = &ctx->options.options_val[i];
        if (val->option.octet_string_len == sizeof(EXP_CTX_TYPE_OPTION) &&
            strncmp(EXP_CTX_TYPE_OPTION,
                        val->option.octet_string_val,
                        val->option.octet_string_len) == 0) {
            if (strncmp(LINUX_LUCID_V1,
                        val->value.octet_string_val,
                        val->value.octet_string_len) == 0) {
                return EXP_CTX_LINUX_LUCID_V1;
            }
            return -1;
        }
    }

    return EXP_CTX_DEFAULT;
}

uint32_t gp_export_ctx_id_to_gssx(uint32_t *min, int type,
                                  gss_ctx_id_t *in, gssx_ctx *out)
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

    /* we do not need the client to release anything until we handle state */
    out->needs_release = false;

    ret_maj = gss_inquire_context(&ret_min, *in, &src_name, &targ_name,
                                  &lifetime_rec, &mech_type, &ctx_flags,
                                  &is_locally_initiated, &is_open);
    if (ret_maj) {
        goto done;
    }

    ret = gp_conv_oid_to_gssx(mech_type, &out->mech);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret_maj = gp_conv_name_to_gssx(&ret_min, src_name, &out->src_name);
    if (ret_maj) {
        goto done;
    }

    ret_maj = gp_conv_name_to_gssx(&ret_min, targ_name, &out->targ_name);
    if (ret_maj) {
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
    ret_maj = gss_export_sec_context(&ret_min, in, &export_buffer);
    if (ret_maj) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    ret = gp_conv_buffer_to_gssx(&export_buffer, &out->exported_context_token);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    /* Leave this empty, used only on the way in for init_sec_context */
    /* out->gssx_option */

done:
    *min = ret_min;
    gss_release_name(&ret_min, &src_name);
    gss_release_name(&ret_min, &targ_name);
    gss_release_buffer(&ret_min, &export_buffer);
    if (ret_maj) {
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->mech);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->src_name);
        xdr_free((xdrproc_t)xdr_gssx_name, (char *)&out->targ_name);
    }
    return ret_maj;
}

uint32_t gp_import_gssx_to_ctx_id(uint32_t *min, int type,
                                  gssx_ctx *in, gss_ctx_id_t *out)
{
    gss_buffer_desc export_buffer = GSS_C_EMPTY_BUFFER;

    if (type != EXP_CTX_DEFAULT) {
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    gp_conv_gssx_to_buffer(&in->exported_context_token, &export_buffer);

    return gss_import_sec_context(min, &export_buffer, out);
}

