/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "gp_conv.h"
#include "gp_export.h"
#include "gp_debug.h"
#include "gp_proxy.h"
#include <gssapi/gssapi_krb5.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>

#define GP_CREDS_HANDLE_KEY_ENCTYPE ENCTYPE_AES256_CTS_HMAC_SHA1_96

struct gp_creds_handle {
    krb5_context context;
    krb5_keyblock *key;
};

void gp_free_creds_handle(struct gp_creds_handle **in)
{
    struct gp_creds_handle *handle = *in;

    if (!handle) {
        return;
    }

    if (handle->context) {
        krb5_free_keyblock(handle->context, handle->key);
        krb5_free_context(handle->context);
    }

    free(handle);
    *in = NULL;
    return;
}

uint32_t gp_init_creds_with_keytab(uint32_t *min, const char *svc_name,
                                   const char *keytab,
                                   struct gp_creds_handle *handle)
{
    char ktname[MAX_KEYTAB_NAME_LEN + 1] = {0};
    krb5_keytab ktid = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    krb5_enctype *permitted = NULL;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    int ret;

    if (keytab) {
        strncpy(ktname, keytab, MAX_KEYTAB_NAME_LEN);
        ret = krb5_kt_resolve(handle->context, keytab, &ktid);
    }
    /* if the keytab is not specified or fails to resolve try default */
    if (!keytab || ret != 0) {
        ret = krb5_kt_default_name(handle->context, ktname,
                                   MAX_KEYTAB_NAME_LEN);
        if (ret) {
            strncpy(ktname, "[default]", MAX_KEYTAB_NAME_LEN);
        }
        ret = krb5_kt_default(handle->context, &ktid);
    }
    if (ret == 0) {
        ret = krb5_kt_have_content(handle->context, ktid);
    }
    if (ret) {
        GPDEBUG("Keytab %s has no content (%d)\n", ktname, ret);
        ret_min = ret;
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    ret = krb5_get_permitted_enctypes(handle->context, &permitted);
    if (ret) {
        GPDEBUG("Failed to source permitted enctypes (%d)\n", ret);
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret = krb5_kt_start_seq_get(handle->context, ktid, &cursor);
    if (ret) {
        GPDEBUG("krb5_kt_start_seq_get() failed (%d)\n", ret);
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    do {
        ret = krb5_kt_next_entry(handle->context, ktid, &entry, &cursor);
        if (ret == 0) {
            for (unsigned i = 0; permitted[i] != 0; i++) {
                if (permitted[i] == entry.key.enctype) {
                    /* should we derive a key instead ? */
                    ret = krb5_copy_keyblock(handle->context, &entry.key,
                                             &handle->key);
                    if (ret == 0) {
                        GPDEBUG("Service: %s, Keytab: %s, Enctype: %d\n",
                                svc_name, ktname, entry.key.enctype);
                        ret = KRB5_KT_END;
                    } else {
                        GPDEBUG("krb5_copy_keyblock failed (%d)\n", ret);
                    }
                    break;
                }
            }
            (void)krb5_free_keytab_entry_contents(handle->context, &entry);
        }
    } while (ret == 0);
    (void)krb5_kt_end_seq_get(handle->context, ktid, &cursor);
    if ((ret == KRB5_KT_END) && (handle->key == NULL)) {
        ret = KRB5_WRONG_ETYPE;
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }
    if (ret != KRB5_KT_END) {
        ret_min = ret;
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    krb5_free_enctypes(handle->context, permitted);
    if (ktid) {
        (void)krb5_kt_close(handle->context, ktid);
    }
    *min = ret_min;
    return ret_maj;
}

uint32_t gp_init_creds_handle(uint32_t *min, const char *svc_name,
                              const char *keytab,
                              struct gp_creds_handle **out)
{
    struct gp_creds_handle *handle;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    int ret;

    handle = calloc(1, sizeof(struct gp_creds_handle));
    if (!handle) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    /* initialize key */
    ret = krb5_init_context(&handle->context);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    /* Try to use a keytab, and fall back to a random runtime secret if all
     * else fails */
    ret_maj = gp_init_creds_with_keytab(&ret_min, svc_name, keytab, handle);
    if (ret_maj != GSS_S_COMPLETE) {
        /* fallback */
        ret = krb5_init_keyblock(handle->context,
                                 GP_CREDS_HANDLE_KEY_ENCTYPE, 0,
                                 &handle->key);
        if (ret == 0) {
            ret = krb5_c_make_random_key(handle->context, handle->key->enctype,
                                         handle->key);
            GPDEBUG("Service: %s, Enckey: [ephemeral], Enctype: %d\n",
                    svc_name, handle->key->enctype);
        }
        if (ret) {
            ret_min = ret;
            ret_maj = GSS_S_FAILURE;
            goto done;
        }
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    *min = ret_min;
    if (ret_maj) {
        gp_free_creds_handle(&handle);
    }
    *out = handle;

    return ret_maj;
}

static int gp_encrypt_buffer(krb5_context context, krb5_keyblock *key,
                             size_t len, void *buf, octet_string *out)
{
    int ret;
    krb5_data data_in;
    krb5_enc_data enc_handle;
    size_t cipherlen;

    data_in.length = len;
    data_in.data = buf;

    memset(&enc_handle, '\0', sizeof(krb5_enc_data));

    ret = krb5_c_encrypt_length(context,
                                key->enctype,
                                data_in.length,
                                &cipherlen);
    if (ret) {
        goto done;
    }

    enc_handle.ciphertext.length = cipherlen;
    enc_handle.ciphertext.data = malloc(enc_handle.ciphertext.length);
    if (!enc_handle.ciphertext.data) {
        ret = ENOMEM;
        goto done;
    }

    ret = krb5_c_encrypt(context,
                         key,
                         KRB5_KEYUSAGE_APP_DATA_ENCRYPT,
                         NULL,
                         &data_in,
                         &enc_handle);
    if (ret) {
        ret = EINVAL;
        goto done;
    }

    ret = gp_conv_octet_string(enc_handle.ciphertext.length,
                               enc_handle.ciphertext.data,
                               out);
    if (ret) {
        goto done;
    }

done:
    free(enc_handle.ciphertext.data);
    return ret;
}

static int gp_decrypt_buffer(krb5_context context, krb5_keyblock *key,
                             octet_string *in, size_t *len, void *buf)
{
    int ret;
    krb5_data data_out;
    krb5_enc_data enc_handle;

    memset(&enc_handle, '\0', sizeof(krb5_enc_data));

    enc_handle.enctype = key->enctype;
    enc_handle.ciphertext.data = in->octet_string_val;
    enc_handle.ciphertext.length = in->octet_string_len;

    data_out.length = *len;
    data_out.data = buf;

    ret = krb5_c_decrypt(context,
                         key,
                         KRB5_KEYUSAGE_APP_DATA_ENCRYPT,
                         NULL,
                         &enc_handle,
                         &data_out);
    if (ret) {
        return ret;
    }

    *len = data_out.length;

    return 0;
}

uint32_t gp_export_gssx_cred(uint32_t *min, struct gp_call_ctx *gpcall,
                             gss_cred_id_t *in, gssx_cred *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t name = NULL;
    uint32_t lifetime;
    gss_cred_usage_t cred_usage;
    gss_OID_set mechanisms = NULL;
    uint32_t initiator_lifetime = 0;
    uint32_t acceptor_lifetime = 0;
    struct gssx_cred_element *el;
    int ret;
    struct gp_creds_handle *handle = NULL;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;

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

    out->elements.elements_val = calloc(mechanisms->count,
                                        sizeof(gssx_cred_element));
    if (!out->elements.elements_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    out->elements.elements_len = mechanisms->count;

    for (unsigned i = 0, j = 0; i < mechanisms->count; i++, j++) {
        el = &out->elements.elements_val[j];

        ret_maj = gss_inquire_cred_by_mech(&ret_min, *in,
                                           &mechanisms->elements[i],
                                           &name,
                                           &initiator_lifetime,
                                           &acceptor_lifetime,
                                           &cred_usage);
        if (ret_maj) {
            gp_log_failure(&mechanisms->elements[i], ret_maj, ret_min);

            /* skip any offender */
            out->elements.elements_len--;
            j--;
            continue;
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
        el->cred_usage = gp_conv_cred_usage_to_gssx(cred_usage);

        el->initiator_time_rec = initiator_lifetime;
        el->acceptor_time_rec = acceptor_lifetime;
    }

    handle = gp_service_get_creds_handle(gpcall->service);
    if (!handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gss_export_cred(&ret_min, *in, &token);
    if (ret_maj) {
        goto done;
    }

    ret = gp_encrypt_buffer(handle->context, handle->key,
                            token.length, token.value,
                            &out->cred_handle_reference);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }
    out->needs_release = false;
    /* now we have serialized creds in the hands of the client.
     * we can safey free them here so that we can remain sateless and
     * not leak memory */
    gss_release_cred(&ret_min, in);

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    *min = ret_min;
    gss_release_buffer(&ret_min, &token);
    gss_release_name(&ret_min, &name);
    gss_release_oid_set(&ret_min, &mechanisms);
    return ret_maj;
}

#define KRB5_SET_ALLOWED_ENCTYPE "krb5_set_allowed_enctype_values"
#define KRB5_SET_NO_CI_FLAGS "krb5_set_no_ci_flags"

static void gp_set_cred_options(gssx_cred *cred, gss_cred_id_t gss_cred)
{
    struct gssx_cred_element *ce;
    struct gssx_option *op;
    uint32_t num_ktypes = 0;
    krb5_enctype *ktypes;
    bool no_ci_flags = false;
    uint32_t maj, min;

    for (unsigned i = 0; i < cred->elements.elements_len; i++) {
        ce = &cred->elements.elements_val[i];
        for (unsigned j = 0; j < ce->options.options_len; j++) {
            op = &ce->options.options_val[j];
            if ((op->option.octet_string_len ==
                    sizeof(KRB5_SET_ALLOWED_ENCTYPE)) &&
                (strncmp(KRB5_SET_ALLOWED_ENCTYPE,
                         op->option.octet_string_val,
                         op->option.octet_string_len) == 0)) {
                num_ktypes = op->value.octet_string_len / sizeof(krb5_enctype);
                ktypes = (krb5_enctype *)op->value.octet_string_val;
                break;
            } else if ((op->option.octet_string_len ==
                        sizeof(KRB5_SET_NO_CI_FLAGS)) &&
                (strncmp(KRB5_SET_NO_CI_FLAGS,
                         op->option.octet_string_val,
                         op->option.octet_string_len) == 0)) {
                no_ci_flags = true;
            }
        }
    }

    if (num_ktypes) {
        maj = gss_krb5_set_allowable_enctypes(&min, gss_cred,
                                              num_ktypes, ktypes);
        if (maj != GSS_S_COMPLETE) {
            GPDEBUG("Failed to set allowable enctypes\n");
        }
    }

    if (no_ci_flags) {
        gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;
        maj = gss_set_cred_option(&min, &gss_cred,
                                  discard_const(GSS_KRB5_CRED_NO_CI_FLAGS_X),
                                  &empty_buffer);
        if (maj != GSS_S_COMPLETE) {
            GPDEBUG("Failed to set NO CI Flags\n");
        }
    }
}

uint32_t gp_import_gssx_cred(uint32_t *min, struct gp_call_ctx *gpcall,
                             gssx_cred *cred, gss_cred_id_t *out)
{
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    struct gp_creds_handle *handle = NULL;
    uint32_t ret_maj = GSS_S_COMPLETE;
    uint32_t ret_min = 0;
    int ret;

    *out = GSS_C_NO_CREDENTIAL;

    handle = gp_service_get_creds_handle(gpcall->service);
    if (!handle) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    token.length = cred->cred_handle_reference.octet_string_len;
    token.value = malloc(token.length);
    if (!token.value) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    ret = gp_decrypt_buffer(handle->context, handle->key,
                            &cred->cred_handle_reference,
                            &token.length, token.value);
    if (ret) {
        /* Allow for re-issuance of the keytab. */
        GPDEBUG("Stored ccache failed to decrypt; treating as empty\n");
        goto done;
    }

    ret_maj = gss_import_cred(&ret_min, &token, out);

    /* check if there is any client option we need to set on credentials */
    gp_set_cred_options(cred, *out);

done:
    *min = ret_min;
    free(token.value);
    return ret_maj;
}

/* Exported Contexts */

#define EXP_CTX_TYPE_OPTION "exported_context_type"
#define LINUX_LUCID_V1      "linux_lucid_v1"

enum exp_ctx_types {
    EXP_CTX_PARTIAL = -1, /* cannot be specified by client */
    EXP_CTX_DEFAULT = 0,
    EXP_CTX_LINUX_LUCID_V1 = 1,
};

int gp_get_exported_context_type(struct gssx_call_ctx *ctx)
{

    struct gssx_option *val = NULL;

    gp_options_find(val, ctx->options,
                    EXP_CTX_TYPE_OPTION, sizeof(EXP_CTX_TYPE_OPTION));
    if (val) {
        if (gp_option_value_match(val, LINUX_LUCID_V1,
                                  sizeof(LINUX_LUCID_V1))) {
            return EXP_CTX_LINUX_LUCID_V1;
        } else {
            return EXP_CTX_PARTIAL;
        }
    }

    return EXP_CTX_DEFAULT;
}

int gp_get_continue_needed_type(void)
{
    return EXP_CTX_PARTIAL;
}

#define KRB5_CTX_FLAG_INITIATOR         0x00000001
#define KRB5_CTX_FLAG_CFX               0x00000002
#define KRB5_CTX_FLAG_ACCEPTOR_SUBKEY   0x00000004

/* we use what svcgssd calls a "krb5_rfc4121_buffer"
 * Format:  uint32_t flags
 *          int32_t  endtime
 *          uint64_t seq_send
 *          uint32_t enctype
 *          u8[] raw key
 */

static uint32_t gp_format_linux_lucid_v1(uint32_t *min,
                                         gss_krb5_lucid_context_v1_t *lucid,
                                         gssx_buffer *out)
{
    uint8_t *buffer;
    uint8_t *p;
    size_t length;
    uint32_t flags;
    uint32_t enctype;
    uint32_t keysize;
    void *keydata;
    uint32_t maj;

    if (lucid->version != 1 ||
        (lucid->protocol != 0 && lucid->protocol != 1)) {
        *min = ENOTSUP;
        return GSS_S_FAILURE;
    }

    flags = 0;
    if (lucid->initiate) {
        flags |= KRB5_CTX_FLAG_INITIATOR;
    }
    if (lucid->protocol == 1) {
        flags |= KRB5_CTX_FLAG_CFX;
    }
    if (lucid->protocol == 1 && lucid->cfx_kd.have_acceptor_subkey == 1) {
        flags |= KRB5_CTX_FLAG_ACCEPTOR_SUBKEY;
    }

    if (lucid->protocol == 0) {
        enctype = lucid->rfc1964_kd.ctx_key.type;
        keysize = lucid->rfc1964_kd.ctx_key.length;
        keydata = lucid->rfc1964_kd.ctx_key.data;
    } else {
        if (lucid->cfx_kd.have_acceptor_subkey == 1) {
            enctype = lucid->cfx_kd.acceptor_subkey.type;
            keysize = lucid->cfx_kd.acceptor_subkey.length;
            keydata = lucid->cfx_kd.acceptor_subkey.data;
        } else {
            enctype = lucid->cfx_kd.ctx_key.type;
            keysize = lucid->cfx_kd.ctx_key.length;
            keydata = lucid->cfx_kd.ctx_key.data;
        }
    }

    length = sizeof(flags)
             + sizeof(lucid->endtime)
             + sizeof(lucid->send_seq)
             + sizeof(enctype)
             + keysize;

    buffer = calloc(1, length);
    if (!buffer) {
        *min = ENOMEM;
        maj = GSS_S_FAILURE;
        goto done;
    }
    p = buffer;

    memcpy(p, &flags, sizeof(flags));
    p += sizeof(flags);
    memcpy(p, &lucid->endtime, sizeof(lucid->endtime));
    p += sizeof(lucid->endtime);
    memcpy(p, &lucid->send_seq, sizeof(lucid->send_seq));
    p += sizeof(lucid->send_seq);
    memcpy(p, &enctype, sizeof(enctype));
    p += sizeof(enctype);
    memcpy(p, keydata, keysize);

    out->octet_string_val = (void *)buffer;
    out->octet_string_len = length;
    maj = GSS_S_COMPLETE;
    *min = 0;

done:
    if (maj) {
        free(buffer);
    }
    return maj;
}


uint32_t gp_export_ctx_id_to_gssx(uint32_t *min, int type, gss_OID mech,
                                  gss_ctx_id_t *in, gssx_ctx *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_name_t targ_name = GSS_C_NO_NAME;
    gss_buffer_desc export_buffer = GSS_C_EMPTY_BUFFER;
    gss_krb5_lucid_context_v1_t *lucid = NULL;
    uint32_t lifetime_rec;
    gss_OID mech_type;
    uint32_t ctx_flags;
    int is_locally_initiated;
    int is_open;
    int ret;

    /* we do not need the client to release anything until we handle state */
    out->needs_release = false;

    ret_maj = gss_inquire_context(&ret_min, *in, &src_name, &targ_name,
                                  &lifetime_rec, &mech_type, &ctx_flags,
                                  &is_locally_initiated, &is_open);
    if (ret_maj) {
        if (type == EXP_CTX_PARTIAL) {
            /* This may happen on partially established context,
             * so just go on and put in what we can */
            goto export;
        }
        goto done;
    }

    ret = gp_conv_oid_to_gssx(mech_type, &out->mech);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    if (src_name != GSS_C_NO_NAME) {
        ret_maj = gp_conv_name_to_gssx(&ret_min, src_name, &out->src_name);
        if (ret_maj) {
            goto done;
        }
    }

    if (targ_name != GSS_C_NO_NAME) {
        ret_maj = gp_conv_name_to_gssx(&ret_min, targ_name, &out->targ_name);
        if (ret_maj) {
            goto done;
        }
    }

    out->lifetime = lifetime_rec;

    out->ctx_flags = ctx_flags;

    if (is_locally_initiated) {
        out->locally_initiated = true;
    }

    if (is_open) {
        out->open = true;
    }

export:
    /* note: once converted the original context token is not usable anymore,
     * so this must be the last call to use it */
    switch (type) {
    case EXP_CTX_PARTIAL:
        /* this happens only when a init_sec_context call returns a partially
         * initialized context so we return only what we have, not much */
        xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&out->mech);
        ret = gp_conv_oid_to_gssx(mech, &out->mech);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        out->locally_initiated = true;
        out->open = false;

        /* out->state; */

        /* fall through */
    case EXP_CTX_DEFAULT:
        ret_maj = gss_export_sec_context(&ret_min, in, &export_buffer);
        if (ret_maj) {
            goto done;
        }
        ret = gp_conv_buffer_to_gssx(&export_buffer,
                                     &out->exported_context_token);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        break;
    case EXP_CTX_LINUX_LUCID_V1:
        ret_maj = gss_krb5_export_lucid_sec_context(&ret_min, in, 1,
                                                    (void **)&lucid);
        if (ret_maj) {
            goto done;
        }
        ret_maj = gp_format_linux_lucid_v1(&ret_min, lucid,
                                           &out->exported_context_token);
        if (ret_maj) {
            goto done;
        }
        /* suppress names exported_composite_name, the kernel doesn't want
         * this information */
        xdr_free((xdrproc_t)xdr_gssx_buffer,
                 (char *)&out->src_name.exported_composite_name);
        memset(&out->src_name.exported_composite_name, 0,
               sizeof(out->src_name.exported_composite_name));
        xdr_free((xdrproc_t)xdr_gssx_buffer,
                 (char *)&out->targ_name.exported_composite_name);
        memset(&out->targ_name.exported_composite_name, 0,
               sizeof(out->targ_name.exported_composite_name));
        break;
    default:
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    /* Leave this empty, used only on the way in for init_sec_context */
    /* out->gssx_option */

done:
    *min = ret_min;
    gss_release_name(&ret_min, &src_name);
    gss_release_name(&ret_min, &targ_name);
    gss_release_buffer(&ret_min, &export_buffer);
    if (lucid) {
        gss_krb5_free_lucid_sec_context(&ret_min, lucid);
    }
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

/* Exported Creds */

#define EXP_CREDS_TYPE_OPTION "exported_creds_type"
#define LINUX_CREDS_V1        "linux_creds_v1"

enum exp_creds_types {
    EXP_CREDS_NO_CREDS = 0,
    EXP_CREDS_LINUX_V1 = 1,
};

int gp_get_export_creds_type(struct gssx_call_ctx *ctx)
{

    struct gssx_option *val = NULL;

    gp_options_find(val, ctx->options,
                    EXP_CREDS_TYPE_OPTION, sizeof(EXP_CREDS_TYPE_OPTION));
    if (val) {
        if (gp_option_value_match(val, LINUX_CREDS_V1,
                                  sizeof(LINUX_CREDS_V1))) {
            return EXP_CREDS_LINUX_V1;
        }
        return -1;
    }

    return EXP_CREDS_NO_CREDS;
}

#define CREDS_BUF_MAX (NGROUPS_MAX * sizeof(int32_t))
#define CREDS_HDR (3 * sizeof(uint32_t)) /* uid, gid, count */

static uint32_t gp_export_creds_enoent(uint32_t *min, gss_buffer_t buf)
{
    uint32_t *p;

    p = malloc(CREDS_HDR);
    if (!p) {
        *min = ENOMEM;
        return GSS_S_FAILURE;
    }
    p[0] = -1; /* uid */
    p[1] = -1; /* gid */
    p[2] = 0; /* num groups */

    buf->value = p;
    buf->length = CREDS_HDR;
    *min = 0;
    return GSS_S_COMPLETE;
}

static uint32_t gp_export_creds_linux(uint32_t *min, gss_name_t name,
                                      gss_const_OID mech, gss_buffer_t buf)
{
    gss_buffer_desc localname = {};
    uint32_t ret_maj;
    uint32_t ret_min;
    struct passwd pwd, *res;
    char *pwbuf = NULL;
    char *grbuf = NULL;
    uint32_t *p;
    size_t len;
    int count, num;
    int ret;

    /* We use gss_localname() to map the name. Then just use nsswitch to
     * look up the user.
     *
     * (TODO: If gss_localname() fails we may wanto agree with SSSD on a name
     * format to match principal names, es: gss:foo@REALM.COM, or just
     * foo@REALM.COM) until sssd can provide a libkrb5 interface to augment
     * gss_localname() resolution for trusted realms */

    ret_maj = gss_localname(&ret_min, name, mech, &localname);
    if (ret_maj) {
        if (ret_min == ENOENT) {
            return gp_export_creds_enoent(min, buf);
        }
        *min = ret_min;
        return ret_maj;
    }

    len = 1024;
    pwbuf = malloc(len);
    if (!pwbuf) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    ret = 0;
    do {
        if (ret == ERANGE) {
            if (len == CREDS_BUF_MAX) {
                ret_min = ENOSPC;
                ret_maj = GSS_S_FAILURE;
                goto done;
            }
            len *= 2;
            if (len > CREDS_BUF_MAX) {
                len = CREDS_BUF_MAX;
            }
            p = realloc(pwbuf, len);
            if (!p) {
                ret_min = ENOMEM;
                ret_maj = GSS_S_FAILURE;
                goto done;
            }
            pwbuf = (char *)p;
        }
        ret = getpwnam_r((char *)localname.value, &pwd, pwbuf, len, &res);
    } while (ret == EINTR || ret == ERANGE);

    switch (ret) {
    case 0:
        if (res != NULL) {
            break;
        }
        /* ret == NULL is equivalent to ENOENT */
        /* fall through */
    case ENOENT:
    case ESRCH:
        free(pwbuf);
        gss_release_buffer(&ret_min, &localname);
        return gp_export_creds_enoent(min, buf);
    default:
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    /* start with a reasonably sized buffer */
    count = 256;
    num = 0;
    do {
        if (count >= NGROUPS_MAX) {
            ret_min = ENOSPC;
            ret_maj = GSS_S_FAILURE;
            goto done;
        }
        count *= 2;
        if (count < num) {
            count = num;
        }
        if (count > NGROUPS_MAX) {
            count = NGROUPS_MAX;
        }
        len = count * sizeof(int32_t);
        p = realloc(grbuf, len + CREDS_HDR);
        if (!p) {
            ret_min = ENOMEM;
            ret_maj = GSS_S_FAILURE;
            goto done;
        }
        grbuf = (char *)p;
        num = count;
        ret = getgrouplist(pwd.pw_name, pwd.pw_gid, (gid_t *)&p[3], &num);
    } while (ret == -1);

    /* we got the buffer, now fill in [uid, gid, num] and we are done */
    p[0] = pwd.pw_uid;
    p[1] = pwd.pw_gid;
    p[2] = num;
    buf->value = p;
    buf->length = (num + 3) * sizeof(int32_t);
    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    if (ret_maj) {
       free(grbuf);
    }
    free(pwbuf);
    *min = ret_min;
    gss_release_buffer(&ret_min, &localname);
    return ret_maj;
}

uint32_t gp_export_creds_to_gssx_options(uint32_t *min, int type,
                                         gss_name_t src_name,
                                         gss_const_OID mech_type,
                                         unsigned int *opt_num,
                                         gssx_option **opt_array)
{
    gss_buffer_desc export_buffer = GSS_C_EMPTY_BUFFER;
    unsigned int num;
    gssx_option *opta;
    uint32_t ret_min;
    uint32_t ret_maj;

    switch (type) {
    case EXP_CREDS_NO_CREDS:
        *min = 0;
        return GSS_S_COMPLETE;

    case EXP_CREDS_LINUX_V1:
        ret_maj = gp_export_creds_linux(&ret_min, src_name,
                                        mech_type, &export_buffer);
        if (ret_maj) {
            if (ret_min == ENOENT) {
                /* if not user, return w/o adding anything to the array */
                ret_min = 0;
                ret_maj = GSS_S_COMPLETE;
            }
            *min = ret_min;
            return ret_maj;
        }
        break;

    default:
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    num = *opt_num;
    opta = realloc(*opt_array, sizeof(gssx_option) * (num + 1));
    if (!opta) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    *opt_array = opta;

    opta[num].option.octet_string_val = strdup(LINUX_CREDS_V1);
    if (!opta[num].option.octet_string_val) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    opta[num].option.octet_string_len = sizeof(LINUX_CREDS_V1);
    opta[num].value.octet_string_val = export_buffer.value;
    opta[num].value.octet_string_len = export_buffer.length;

    num++;
    *opt_num = num;
    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    *min = ret_min;
    if (ret_maj) {
        gss_release_buffer(&ret_min, &export_buffer);
    }
    return ret_maj;
}
