/* Copyright (C) 2016 the GSS-PROXY contributors; see COPYING for license */

#include "t_utils.h"
#include <unistd.h>

int main(int argc, const char *argv[])
{
    uint32_t major, minor;
    gss_key_value_set_desc store = {};
    int ret = -1;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_OID_set_desc oid_set = { 1, discard_const(gss_mech_krb5) };

    if (argc != 3) {
        DEBUG("Usage: %s source_ccache dest_ccache\n", argv[0]);
        goto done;
    }

    store.elements = calloc(1, sizeof(struct gss_key_value_element_struct));
    if (!store.elements) {
        DEBUG("calloc failed\n");
        goto done;
    }
    store.count = 1;
    store.elements[0].key = "ccache";

    /* Acquire initial cred handle from store */
    store.elements[0].value = argv[1];
    major = gss_acquire_cred_from(&minor,
                                  GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE,
                                  &oid_set,
                                  GSS_C_INITIATE,
                                  &store,
                                  &cred_handle,
                                  NULL,
                                  NULL);
    if (major != GSS_S_COMPLETE) {
        DEBUG("gss_acquire_cred_from() failed\n");
        t_log_failure(GSS_C_NO_OID, major, minor);
        goto done;
    }

    /* Test storing credentials */
    store.elements[0].value = argv[2];
    major = gss_store_cred_into(&minor,
                                cred_handle,
                                GSS_C_INITIATE,
                                GSS_C_NO_OID,
                                1,
                                1,
                                &store,
                                NULL,
                                NULL);
    if (major != GSS_S_COMPLETE) {
        DEBUG("gss_store_cred_into() failed\n");
        t_log_failure(GSS_C_NO_OID, major, minor);
        goto done;
    }

    /* Test that we can actually manipulate the stored credentials */
    gss_release_cred(&minor, &cred_handle);
    cred_handle = GSS_C_NO_CREDENTIAL;
    major = gss_acquire_cred_from(&minor,
                                  GSS_C_NO_NAME,
                                  GSS_C_INDEFINITE,
                                  &oid_set,
                                  GSS_C_INITIATE,
                                  &store,
                                  &cred_handle,
                                  NULL,
                                  NULL);
    if (major != GSS_S_COMPLETE) {
        DEBUG("second gss_acquire_cred_from() failed\n");
        t_log_failure(GSS_C_NO_OID, major, minor);
        goto done;
    }

    ret = 0;
done:
    if (store.elements) {
        free(store.elements);
    }
    gss_release_cred(&minor, &cred_handle);
    return ret;
}
