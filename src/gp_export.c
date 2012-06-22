/*
   GSS-PROXY

   Copyright (C) 2011-2012 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>
   Copyright (C) 2012 Guenther Deschner <guenther.deschner@redhat.com>

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
#include "gp_proxy.h"
#include <gssapi/gssapi_krb5.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>

#define GP_RING_BUFFER_KEY_ENCTYPE ENCTYPE_AES256_CTS_HMAC_SHA1_96

struct gp_ring_buffer_cred {
    uint64_t count;
    gss_cred_id_t cred;
};

struct gp_ring_buffer {
    char *name;
    uint32_t end;
    uint64_t count;
    pthread_mutex_t lock;
    struct gp_ring_buffer_cred **creds;
    uint32_t num_creds;
    krb5_keyblock key;
    krb5_context context;
};

struct gp_credential_handle {
    uint32_t index;
    uint64_t count;
};

static void gp_free_ring_buffer_cred(struct gp_ring_buffer_cred *cred)
{
    uint32_t ret_min;

    if (!cred) {
        return;
    }

    gss_release_cred(&ret_min, &cred->cred);

    free(cred);
}

void gp_free_ring_buffer(struct gp_ring_buffer *buffer)
{
    uint32_t i;

    if (!buffer) {
        return;
    }

    free(buffer->name);

    for (i=0; i < buffer->num_creds; i++) {
        gp_free_ring_buffer_cred(buffer->creds[i]);
    }

    free(buffer->creds);

    if (buffer->context) {
        krb5_free_keyblock_contents(buffer->context, &buffer->key);
        krb5_free_context(buffer->context);
    }

    pthread_mutex_destroy(&buffer->lock);

    free(buffer);
}

uint32_t gp_init_ring_buffer(uint32_t *min,
                             const char *name,
                             uint32_t ring_size,
                             struct gp_ring_buffer **buffer_out)
{
    struct gp_ring_buffer *buffer;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    int ret;

    GPDEBUG("gp_init_ring_buffer %s (size: %d)\n", name, ring_size);

    buffer = calloc(1, sizeof(struct gp_ring_buffer));
    if (!buffer) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    buffer->name = strdup(name);
    if (!buffer->name) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    buffer->num_creds = ring_size;

    buffer->creds = calloc(sizeof(struct gp_ring_buffer_cred *), buffer->num_creds);
    if (!buffer->creds) {
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret = pthread_mutex_init(&buffer->lock, NULL);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    /* initialize key */

    ret = krb5_init_context(&buffer->context);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret = krb5_c_make_random_key(buffer->context,
                                 GP_RING_BUFFER_KEY_ENCTYPE,
                                 &buffer->key);
    if (ret) {
        ret_min = ret;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    *min = ret_min;
    if (ret_maj) {
        gp_free_ring_buffer(buffer);
    }
    *buffer_out = buffer;

    return ret_maj;
}

static uint32_t gp_write_gss_cred_to_ring_buffer(uint32_t *min,
                                                 struct gp_ring_buffer *buffer,
                                                 gss_cred_id_t *cred,
                                                 struct gp_credential_handle *handle)
{
    struct gp_ring_buffer_cred *bcred = NULL;

    if (!buffer || !cred) {
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    bcred = calloc(1, sizeof(struct gp_ring_buffer_cred));
    if (!bcred) {
        *min = ENOMEM;
        return GSS_S_FAILURE;
    }

    /* ======> LOCK */
    pthread_mutex_lock(&buffer->lock);

    /* setup ring buffer credential */
    bcred->count = buffer->count;
    bcred->cred = *cred;

    /* setup credential handle */
    handle->count = buffer->count;
    handle->index = buffer->end;

    /* store ring buffer credential */
    gp_free_ring_buffer_cred(buffer->creds[buffer->end]);

    buffer->creds[buffer->end] = bcred;
    buffer->end = (buffer->end + 1) % buffer->num_creds;

    buffer->count++;

    /* <====== LOCK */
    pthread_mutex_unlock(&buffer->lock);

    *min = 0;

    return GSS_S_COMPLETE;
}

static uint32_t gp_read_gss_creds_from_ring_buffer(uint32_t *min,
                                                   struct gp_ring_buffer *buffer,
                                                   struct gp_credential_handle *handle,
                                                   gss_cred_id_t *cred)
{
    struct gp_ring_buffer_cred *bcred;

    if (!buffer || !cred || !handle) {
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    /* some basic sanity checks */
    if (handle->index > buffer->num_creds) {
         *min = EINVAL;
        return GSS_S_FAILURE;
    }

    /* ======> LOCK */
    pthread_mutex_lock(&buffer->lock);

    /* pick ring buffer credential */
    bcred = buffer->creds[handle->index];
    if (bcred &&
        (bcred->count == handle->count)) {
        *cred = bcred->cred;
    } else {
        *cred = NULL;
    }

    /* <====== LOCK */
    pthread_mutex_unlock(&buffer->lock);

    if (*cred == NULL) {
        *min = GSS_S_CRED_UNAVAIL;
        return GSS_S_FAILURE;
    }

    *min = 0;

    return GSS_S_COMPLETE;
}


static int gp_encrypt_buffer(krb5_context context, krb5_keyblock *key,
                             size_t len, void *buf, octet_string *out)
{
    int ret;
    krb5_data data_in;
    krb5_enc_data enc_handle;

    data_in.length = len;
    data_in.data = buf;

    memset(&enc_handle, '\0', sizeof(krb5_enc_data));

    ret = krb5_c_encrypt_length(context,
                                GP_RING_BUFFER_KEY_ENCTYPE,
                                data_in.length,
                                (size_t *)&enc_handle.ciphertext.length);
    if (ret) {
        goto done;
    }

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
                             octet_string *in, size_t len, void *buf)
{
    int ret;
    krb5_data data_out;
    krb5_enc_data enc_handle;

    memset(&enc_handle, '\0', sizeof(krb5_enc_data));

    enc_handle.enctype = GP_RING_BUFFER_KEY_ENCTYPE;
    enc_handle.ciphertext.data = in->octet_string_val;
    enc_handle.ciphertext.length = in->octet_string_len;

    data_out.length = len;
    data_out.data = buf;

    ret = krb5_c_decrypt(context,
                         key,
                         KRB5_KEYUSAGE_APP_DATA_ENCRYPT,
                         NULL,
                         &enc_handle,
                         &data_out);
    if (ret) {
        return EINVAL;
    }

    return 0;
}

uint32_t gp_export_gssx_cred(uint32_t *min,
                             struct gp_service *svc,
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
    struct gp_ring_buffer *ring_buffer = NULL;
    struct gp_credential_handle handle;

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

    ring_buffer = gp_service_get_ring_buffer(svc);
    if (!ring_buffer) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret = gp_write_gss_cred_to_ring_buffer(&ret_min,
                                           ring_buffer,
                                           in,
                                           &handle);
    if (ret) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ret;
        goto done;
    }

    ret = gp_encrypt_buffer(ring_buffer->context, &ring_buffer->key,
                            sizeof(handle), &handle,
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

static int gp_import_gssx_cred(struct gp_ring_buffer *ring_buffer,
                               struct gp_credential_handle *in,
                               gss_cred_id_t *out)
{
    uint32_t ret = 0;
    uint32_t ret_min = 0;

    ret = gp_read_gss_creds_from_ring_buffer(&ret_min,
                                             ring_buffer,
                                             in,
                                             out);
    if (ret) {
        return ret_min;
    }

    return 0;
}



int gp_find_cred_int(struct gp_ring_buffer *ring_buffer, gssx_cred *cred,
                     gss_cred_id_t *out, struct gp_credential_handle *handle)
{
    int ret;

    ret = gp_decrypt_buffer(ring_buffer->context, &ring_buffer->key,
                            &cred->cred_handle_reference,
                            sizeof(*handle), handle);
    if (ret) {
        return ENOENT;
    }

    return gp_import_gssx_cred(ring_buffer, handle, out);
}

int gp_find_cred(struct gp_service *svc, gssx_cred *cred, gss_cred_id_t *out)
{
    struct gp_ring_buffer *ring_buffer;
    struct gp_credential_handle handle;

    ring_buffer = gp_service_get_ring_buffer(svc);
    if (!ring_buffer) {
        return EINVAL;
    }

    return gp_find_cred_int(ring_buffer, cred, out, &handle);
}

int gp_find_and_free_cred(struct gp_service *svc, gssx_cred *cred)
{
    struct gp_ring_buffer *ring_buffer;
    struct gp_credential_handle handle;
    gss_cred_id_t gss_cred;
    int ret;

    ring_buffer = gp_service_get_ring_buffer(svc);
    if (!ring_buffer) {
        return EINVAL;
    }

    ret = gp_find_cred_int(ring_buffer, cred, &gss_cred, &handle);
    if (ret) {
        return ret;
    }

    gp_free_ring_buffer_cred(ring_buffer->creds[handle.index]);

    return 0;
}

/* Exported Contexts */

#define EXP_CTX_TYPE_OPTION "exported_context_type"
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


uint32_t gp_export_ctx_id_to_gssx(uint32_t *min, int type,
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
    switch (type) {
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

    struct gssx_option *val;
    int i;

    for (i = 0; i < ctx->options.options_len; i++) {
        val = &ctx->options.options_val[i];
        if (val->option.octet_string_len == sizeof(EXP_CREDS_TYPE_OPTION) &&
            strncmp(EXP_CREDS_TYPE_OPTION,
                        val->option.octet_string_val,
                        val->option.octet_string_len) == 0) {
            if (strncmp(LINUX_CREDS_V1,
                        val->value.octet_string_val,
                        val->value.octet_string_len) == 0) {
                return EXP_CREDS_LINUX_V1;
            }
            return -1;
        }
    }

    return EXP_CREDS_NO_CREDS;
}

#define CREDS_BUF_MAX (NGROUPS_MAX * sizeof(int32_t))
#define CREDS_HDR (3 * sizeof(int32_t)) /* uid, gid, count */

static uint32_t gp_export_creds_enoent(uint32_t *min, gss_buffer_t buf)
{
    int32_t *p;

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
    gss_buffer_desc localname;
    uint32_t ret_maj;
    uint32_t ret_min;
    struct passwd pwd, *res;
    char *pwbuf = NULL;
    char *grbuf = NULL;
    int32_t *p;
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
        /* fall through as ret == NULL is equivalent to ENOENT */
    case ENOENT:
    case ESRCH:
        free(pwbuf);
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
    *opt_array = opta;
    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    *min = ret_min;
    if (ret_maj) {
        gss_release_buffer(&ret_min, &export_buffer);
    }
    return ret_maj;
}
