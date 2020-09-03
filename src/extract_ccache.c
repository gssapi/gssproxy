/* Copyright (C) 2020 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "gp_proxy.h"
#include <gssapi/gssapi_krb5.h>

int extract_ccache(char *ccache_name, char *dest_ccache)
{
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_creds cred = { 0 };
    krb5_creds icred = { 0 };
    krb5_enc_data enc_handle = { 0 };
    krb5_data data_out = { 0 };
    krb5_error_code ret;
    gssx_cred xcred = { 0 };
    XDR xdrctx;
    bool xdrok;
    struct gp_creds_handle *handle = NULL;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t gcred = NULL;
    gss_key_value_element_desc element;
    gss_key_value_set_desc store;
    gss_key_value_set_desc *store_p = NULL;
    uint32_t ret_maj = GSS_S_COMPLETE;
    uint32_t ret_min = 0;
    uint8_t pad;
    size_t last_byte;
    size_t i;

    ret = krb5_init_context(&ctx);
    if (ret) goto done;

    ret = krb5_cc_resolve(ctx, ccache_name, &ccache);
    if (ret) goto done;

    ret = krb5_cc_get_principal(ctx, ccache, &icred.client);
    if (ret) goto done;

    ret = krb5_parse_name(ctx, GPKRB_SRV_NAME, &icred.server);
    if (ret) goto done;

    ret = krb5_cc_retrieve_cred(ctx, ccache, 0, &icred, &cred);
    if (ret) goto done;

    xdrmem_create(&xdrctx, cred.ticket.data, cred.ticket.length, XDR_DECODE);
    xdrok = xdr_gssx_cred(&xdrctx, &xcred);
    if (!xdrok) {
        ret = EIO;
        goto done;
    }

    ret_maj = gp_init_creds_handle(&ret_min, "Extract Ccache", NULL, &handle);
    if (ret_maj) {
        ret = ret_min;
        goto done;
    }

    enc_handle.enctype = handle->key->enctype;
    enc_handle.ciphertext.data =
        xcred.cred_handle_reference.octet_string_val;
    enc_handle.ciphertext.length =
        xcred.cred_handle_reference.octet_string_len;

    data_out.length = enc_handle.ciphertext.length;
    data_out.data = malloc(enc_handle.ciphertext.length);
    if (!data_out.data) {
        ret = ENOMEM;
        goto done;
    }

    ret = krb5_c_decrypt(handle->context, handle->key,
                         KRB5_KEYUSAGE_APP_DATA_ENCRYPT,
                         NULL, &enc_handle, &data_out);
    if (ret) goto done;
    fprintf(stderr, "decrypted\n");

    /* Handle the padding. */
    last_byte = data_out.length - 1;
    pad = data_out.data[last_byte];
    if (pad >= ENC_MIN_PAD_LEN && pad < last_byte) {
        for (i = last_byte - pad; i <= last_byte; i++) {
            if (pad != data_out.data[i]) break;
        }
        if (i == last_byte) {
            /* they all match, this is padding, remove it */
            data_out.length -= pad;
        }
    }

    token.value = data_out.data;
    token.length = data_out.length;
    ret_maj = gss_import_cred(&ret_min, &token, &gcred);
    if (ret_maj) {
        gp_log_failure(GSS_C_NULL_OID, ret_maj, ret_min);
        ret = ret_min;
        goto done;
    }

    /* store in destination ccache if any, or default ccache */
    if (dest_ccache) {
        element.key = "ccache";
        element.value = dest_ccache;
        store.elements = &element;
        store.count = 1;
        store_p = &store;
    }

    ret_maj = gss_store_cred_into(&ret_min, gcred, GSS_C_BOTH,
                                  GSS_C_NULL_OID, 1, 1, store_p, NULL, NULL);
    if (ret_maj) {
        gp_log_failure(GSS_C_NULL_OID, ret_maj, ret_min);
        ret = ret_min;
        goto done;
    }

done:
    if (ctx) {
        krb5_free_cred_contents(ctx, &cred);
        krb5_free_cred_contents(ctx, &icred);
        if (ccache) krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
    }
    xdr_free((xdrproc_t)xdr_gssx_cred, (char *)&xcred);
    gp_free_creds_handle(&handle);
    gss_release_cred(&ret_min, &gcred);
    free(data_out.data);
    return ret;
}
