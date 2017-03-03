/* Copyright (C) 2017 the GSS-PROXY contributors, see COPYING for license */

#include "t_utils.h"
#include <unistd.h>
#include <stdbool.h>

int main(int argc, const char *argv[])
{
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t init_ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_name_t user_name;
    gss_name_t target_name;
    gss_OID_set_desc oid_set = { 1, discard_const(gss_mech_krb5) };
    uint32_t ret_maj;
    uint32_t ret_min;
    uint32_t flags = GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG;
    uint32_t ret_flags = 0;
    int ret = -1;
    gss_key_value_element_desc ccelement = { "ccache", NULL };
    gss_key_value_set_desc cred_store = { 1, &ccelement };
    krb5_enctype enc = ENCTYPE_AES256_CTS_HMAC_SHA1_96;

    if (argc < 3) return -1;

    ret = t_string_to_name(argv[1], &user_name, GSS_C_NT_USER_NAME);
    if (ret) {
        DEBUG("Failed to import user name from argv[1]\n");
        ret = -1;
        goto done;
    }

    ret = t_string_to_name(argv[2], &target_name,
                           GSS_C_NT_HOSTBASED_SERVICE);
    if (ret) {
        DEBUG("Failed to import server name from argv[2]\n");
        ret = -1;
        goto done;
    }

    ccelement.value = argv[3];

    ret_maj = gss_acquire_cred_from(&ret_min,
                                    user_name,
                                    GSS_C_INDEFINITE,
                                    &oid_set,
                                    GSS_C_INITIATE,
                                    &cred_store,
                                    &cred_handle,
                                    NULL, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_acquire_cred_from() [%s,%s] failed\n", argv[1], argv[3]);
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    ret_maj = gss_set_cred_option(&ret_min, &cred_handle,
                                  (gss_OID)GSS_KRB5_CRED_NO_CI_FLAGS_X,
                                  &empty_buffer);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_set_cred_option(GSS_KRB5_CRED_NO_CI_FLAGS_X) failed\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    ret_maj = gss_krb5_set_allowable_enctypes(&ret_min, cred_handle, 1, &enc);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_krb5_set_allowable_enctypes() failed\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    ret_maj = gss_init_sec_context(&ret_min,
                                   cred_handle,
                                   &init_ctx,
                                   target_name,
                                   GSS_C_NO_OID,
                                   flags,
                                   0,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &in_token,
                                   NULL,
                                   &out_token,
                                   NULL,
                                   NULL);
    if (ret_maj != GSS_S_CONTINUE_NEEDED) {
        DEBUG("gss_init_sec_context() failed\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    /* We get stuff from stdin and spit it out on stderr */
    if (!out_token.length) {
        DEBUG("No output token ?");
        ret = -1;
        goto done;
    }

    /* in/out token inverted here intentionally */
    ret_maj = gss_accept_sec_context(&ret_min,
                                     &accept_ctx,
                                     GSS_C_NO_CREDENTIAL,
                                     &out_token,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     NULL,
                                     NULL,
                                     &in_token,
                                     &ret_flags,
                                     NULL,
                                     NULL);
    if (ret_maj) {
        DEBUG("Error accepting context\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    /* now test that flags are as expected */
    if (ret_flags & (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG)) {
        DEBUG("Set NO CI Flags but ret_flags matches (%x)!\n", ret_flags);
        ret = -1;
        goto done;
    }

    if (!in_token.length) {
        DEBUG("No output token ?");
        ret = -1;
        goto done;
    }

    gss_release_buffer(&ret_min, &out_token);

    ret_maj = gss_init_sec_context(&ret_min,
                                   cred_handle,
                                   &init_ctx,
                                   target_name,
                                   GSS_C_NO_OID,
                                   flags,
                                   0,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   &in_token,
                                   NULL,
                                   &out_token,
                                   NULL,
                                   NULL);
    if (ret_maj) {
        DEBUG("Error initializing context\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    ret = 0;

done:
    gss_release_buffer(&ret_min, &in_token);
    gss_release_buffer(&ret_min, &out_token);
    gss_release_cred(&ret_min, &cred_handle);
    return ret;
}
