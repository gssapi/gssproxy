/* Copyright (C) 2015 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"
#include <gssapi/gssapi_krb5.h>

#define GPKRB_SRV_NAME "Encrypted/Credentials/v1@X-GSSPROXY:"

uint32_t gpp_cred_handle_init(uint32_t *min, bool defcred, const char *ccache,
                              struct gpp_cred_handle **out_handle)
{
    struct gpp_cred_handle *h = NULL;
    uint32_t maj = 0;

    h = calloc(1, sizeof(struct gpp_cred_handle));
    if (!h) {
        *min = ENOMEM;
        return GSS_S_FAILURE;
    }

    h->default_creds = defcred;

    if (ccache) {
        h->store.elements = calloc(1, sizeof(gss_key_value_element_desc));
        if (!h->store.elements) {
            *min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
        h->store.count = 1;

        h->store.elements[0].key = strdup("ccache");
        if (!h->store.elements[0].key) {
            *min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }

        h->store.elements[0].value = strdup(ccache);
        if (!h->store.elements[0].value) {
            *min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
    }

done:
    if (maj) {
        uint32_t tmp;
        (void)gpp_cred_handle_free(&tmp, h);
    } else {
        *out_handle = h;
    }
    return maj;
}

uint32_t gpp_cred_handle_free(uint32_t *min, struct gpp_cred_handle *handle)
{
    uint32_t maj = GSS_S_COMPLETE;

    *min = 0;

    if (!handle) {
        return GSS_S_COMPLETE;
    }

    if (handle->local) {
        maj = gss_release_cred(min, &handle->local);
    }

    if (handle->remote) {
        xdr_free((xdrproc_t)xdr_gssx_cred, (char *)handle->remote);
        free(handle->remote);
    }

    if (handle->store.count > 0) {
        for (size_t i = 0; i < handle->store.count; i++) {
            free((void *)handle->store.elements[i].key);
            free((void *)handle->store.elements[i].value);
        }
        free(handle->store.elements);
        handle->store.count = 0;
    }

    free(handle);
    return maj;
}

/* NOTE: currently the only things we check for are the cred name and the
 * cred_handle_reference.  We do NOT check each cred element beyond that they
 * match in number */
bool gpp_creds_are_equal(gssx_cred *a, gssx_cred *b)
{
    gssx_buffer *ta;
    gssx_buffer *tb;

    if (!a && !b) {
        return true;
    } else if (!a || !b) {
        return false;
    }

    ta = &a->desired_name.display_name;
    tb = &b->desired_name.display_name;
    if (ta->octet_string_len != tb->octet_string_len) {
        return false;
    } else if (!ta->octet_string_val && tb->octet_string_val) {
        return false;
    } else if (ta->octet_string_val) {
        if (!tb->octet_string_val) {
            return false;
        } else if (memcmp(ta->octet_string_val, tb->octet_string_val,
                   ta->octet_string_len) != 0) {
            return false;
        }
    }

    if (a->elements.elements_len != b->elements.elements_len) {
        return false;
    }

    ta = &a->cred_handle_reference;
    tb = &b->cred_handle_reference;
    if (ta->octet_string_len != tb->octet_string_len) {
        return false;
    } else if (!ta->octet_string_val && tb->octet_string_val) {
        return false;
    } else if (ta->octet_string_val) {
        if (!tb->octet_string_val) {
            return false;
        } else if (memcmp(ta->octet_string_val, tb->octet_string_val,
                   ta->octet_string_len) != 0) {
            return false;
        }
    }

    return true;
}

static krb5_error_code gpp_construct_cred(gssx_cred *creds, krb5_context ctx,
                                          krb5_creds *cred, char *cred_name)
{
    XDR xdrctx;
    bool xdrok;
    krb5_error_code ret = 0;

    memset(cred, 0, sizeof(*cred));

    memcpy(cred_name, creds->desired_name.display_name.octet_string_val,
           creds->desired_name.display_name.octet_string_len);
    cred_name[creds->desired_name.display_name.octet_string_len] = '\0';

    ret = krb5_parse_name(ctx, cred_name, &cred->client);
    if (ret) {
        return ret;
    }

    ret = krb5_parse_name(ctx, GPKRB_SRV_NAME, &cred->server);
    if (ret) {
        return ret;
    }

    cred->ticket.data = malloc(GPKRB_MAX_CRED_SIZE);
    xdrmem_create(&xdrctx, cred->ticket.data, GPKRB_MAX_CRED_SIZE,
                  XDR_ENCODE);
    xdrok = xdr_gssx_cred(&xdrctx, creds);
    if (!xdrok) {
        return ENOSPC;
    }
    cred->ticket.length = xdr_getpos(&xdrctx);
    return 0;
}

uint32_t gpp_store_remote_creds(uint32_t *min, bool default_creds,
                                gss_const_key_value_set_t cred_store,
                                gssx_cred *creds)
{
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_creds cred;
    krb5_error_code ret;
    char cred_name[creds->desired_name.display_name.octet_string_len + 1];
    const char *cc_type;

    *min = 0;

    ret = krb5_init_context(&ctx);
    if (ret) goto done;

    ret = gpp_construct_cred(creds, ctx, &cred, cred_name);
    if (ret) {
        goto done;
    }

    if (cred_store) {
        for (unsigned i = 0; i < cred_store->count; i++) {
            if (strcmp(cred_store->elements[i].key, "ccache") == 0) {
                ret = krb5_cc_resolve(ctx, cred_store->elements[i].value,
                                      &ccache);
                if (ret) goto done;
                break;
            }
        }
    }
    if (!ccache) {
        if (!default_creds) {
            ret = ENOMEDIUM;
            goto done;
        }
        ret = krb5_cc_default(ctx, &ccache);
        if (ret) goto done;
    }

    cc_type = krb5_cc_get_type(ctx, ccache);
    if (strcmp(cc_type, "FILE") == 0) {
        /* FILE ccaches don't handle updates properly: if they have the same
         * principal name, they are blackholed.  We either have to change the
         * name (at which point the file grows forever) or flash the cache on
         * every update. */
        ret = krb5_cc_initialize(ctx, ccache, cred.client);
        if (ret != 0) {
            goto done;
        }
    }

    ret = krb5_cc_store_cred(ctx, ccache, &cred);

done:
    if (ctx) {
        krb5_free_cred_contents(ctx, &cred);
        if (ccache) krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
    }
    *min = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32 gppint_retrieve_remote_creds(uint32_t *min, const char *ccache_name,
                                       gssx_name *name, gssx_cred *creds)
{
    krb5_context ctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_creds cred;
    krb5_creds icred;
    krb5_error_code ret;
    XDR xdrctx;
    bool xdrok;

    memset(&cred, 0, sizeof(krb5_creds));
    memset(&icred, 0, sizeof(krb5_creds));

    ret = krb5_init_context(&ctx);
    if (ret) goto done;

    if (ccache_name) {
        ret = krb5_cc_resolve(ctx, ccache_name, &ccache);
    } else {
        ret = krb5_cc_default(ctx, &ccache);
    }
    if (ret) goto done;

    if (name) {
        char client_name[name->display_name.octet_string_len + 1];
        memcpy(client_name, name->display_name.octet_string_val,
               name->display_name.octet_string_len);
        client_name[name->display_name.octet_string_len] = '\0';

        ret = krb5_parse_name(ctx, client_name, &icred.client);
    } else {
        ret = krb5_cc_get_principal(ctx, ccache, &icred.client);
    }
    if (ret) goto done;

    ret = krb5_parse_name(ctx, GPKRB_SRV_NAME, &icred.server);
    if (ret) goto done;

    ret = krb5_cc_retrieve_cred(ctx, ccache, 0, &icred, &cred);
    if (ret) goto done;

    xdrmem_create(&xdrctx, cred.ticket.data, cred.ticket.length, XDR_DECODE);
    xdrok = xdr_gssx_cred(&xdrctx, creds);

    if (xdrok) {
        ret = 0;
    } else {
        ret = EIO;
    }

done:
    if (ctx) {
        krb5_free_cred_contents(ctx, &cred);
        krb5_free_cred_contents(ctx, &icred);
        if (ccache) krb5_cc_close(ctx, ccache);
        krb5_free_context(ctx);
    }
    *min = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

static OM_uint32 get_local_def_creds(OM_uint32 *minor_status,
                                     struct gpp_name_handle *name,
                                     gss_cred_usage_t cred_usage,
                                     gss_cred_id_t *cred_handle)
{
    gss_OID_set interposed_mechs = GSS_C_NO_OID_SET;
    gss_OID_set special_mechs = GSS_C_NO_OID_SET;
    OM_uint32 maj, min;

    maj = GSS_S_FAILURE;
    min = 0;

    interposed_mechs = gss_mech_interposer((gss_OID)&gssproxy_mech_interposer);
    if (interposed_mechs == GSS_C_NO_OID_SET) {
        goto done;
    }
    special_mechs = gpp_special_available_mechs(interposed_mechs);
    if (special_mechs == GSS_C_NO_OID_SET) {
        goto done;
    }

    maj = gss_acquire_cred(&min, name ? name->local : NULL, 0, special_mechs,
                           cred_usage, cred_handle, NULL, NULL);
done:
    *minor_status = min;
    (void)gss_release_oid_set(&min, &special_mechs);
    (void)gss_release_oid_set(&min, &interposed_mechs);
    return maj;
}

OM_uint32 gppint_get_def_creds(OM_uint32 *minor_status,
                               enum gpp_behavior behavior,
                               struct gpp_name_handle *name,
                               gss_cred_usage_t cred_usage,
                               struct gpp_cred_handle **cred_handle)
{
    struct gpp_cred_handle *cred;
    OM_uint32 tmaj = GSS_S_COMPLETE;
    OM_uint32 tmin = 0;
    OM_uint32 maj = GSS_S_FAILURE;
    OM_uint32 min = 0;

    if (*cred_handle) {
        cred = *cred_handle;
    } else {
        maj = gpp_cred_handle_init(&min, true, NULL, &cred);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = min;
            return maj;
        }
    }

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = get_local_def_creds(&min, name, cred_usage, &cred->local);
        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (behavior != GPP_LOCAL_ONLY) {
        gssx_cred remote;
        gssx_cred *premote = NULL;

        memset(&remote, 0, sizeof(gssx_cred));

        /* We intentionally ignore failures as finding creds is optional */
        maj = gppint_retrieve_remote_creds(&min, NULL,
                                           name ? name->remote : NULL,
                                           &remote);
        if (maj == GSS_S_COMPLETE) {
            premote = &remote;
        }

        maj = gpm_acquire_cred(&min, premote,
                               NULL, 0, NULL, cred_usage, false,
                               &cred->remote, NULL, NULL);
        if (maj == GSS_S_COMPLETE) {
            if (premote &&
                !gpp_creds_are_equal(premote, cred->remote)) {
                maj = gpp_store_remote_creds(&min, cred->default_creds,
                                             &cred->store, cred->remote);
            }
        }

        xdr_free((xdrproc_t)xdr_gssx_cred, (char *)&remote);

        if (maj == GSS_S_COMPLETE) {
            goto done;
        }

        if (behavior == GPP_REMOTE_FIRST) {
            /* So remote failed, but we can fallback to local, try that */
            maj = get_local_def_creds(&min, name, cred_usage, &cred->local);
        }
    }

done:
    if (maj != GSS_S_COMPLETE && tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    *minor_status = min;
    if (maj != GSS_S_COMPLETE) {
        if (cred != *cred_handle) {
            gssi_release_cred(&min, (gss_cred_id_t *)&cred);
        }
    }
    *cred_handle = cred;
    return maj;
}

OM_uint32 gssi_inquire_cred(OM_uint32 *minor_status,
                            gss_cred_id_t cred_handle,
                            gss_name_t *name,
                            OM_uint32 *lifetime,
                            gss_cred_usage_t *cred_usage,
                            gss_OID_set *mechanisms)
{
    struct gpp_cred_handle *cred = NULL;
    struct gpp_name_handle *gpname = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        maj = gppint_get_def_creds(&min, gpp_get_behavior(), NULL,
                                   GSS_C_INITIATE, &cred);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    } else {
        cred = (struct gpp_cred_handle *)cred_handle;
    }

    if (name) {
        gpname = calloc(1, sizeof(struct gpp_name_handle));
        if (!gpname) {
            min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
    }

    if (cred->local) {
        maj = gss_inquire_cred(&min, cred->local,
                               gpname ? &gpname->local : NULL,
                               lifetime, cred_usage, mechanisms);
    } else if (cred->remote) {
        maj = gpm_inquire_cred(&min, cred->remote,
                               gpname ? &gpname->remote : NULL,
                               lifetime, cred_usage, mechanisms);
    } else {
        min = 0;
        maj = GSS_S_FAILURE;
    }

done:
    *minor_status = gpp_map_error(min);
    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        gssi_release_cred(&min, (gss_cred_id_t*)&cred);
    }
    if (name && maj == GSS_S_COMPLETE) {
        *name = (gss_name_t)gpname;
    } else {
        free(gpname);
    }
    return maj;
}

OM_uint32 gssi_inquire_cred_by_mech(OM_uint32 *minor_status,
                                    gss_cred_id_t cred_handle,
                                    gss_OID mech_type,
                                    gss_name_t *name,
                                    OM_uint32 *initiator_lifetime,
                                    OM_uint32 *acceptor_lifetime,
                                    gss_cred_usage_t *cred_usage)
{
    struct gpp_cred_handle *cred = NULL;
    struct gpp_name_handle *gpname = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        maj = gppint_get_def_creds(&min, gpp_get_behavior(), NULL,
                                   GSS_C_INITIATE, &cred);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    } else {
        cred = (struct gpp_cred_handle *)cred_handle;
    }

    if (name) {
        gpname = calloc(1, sizeof(struct gpp_name_handle));
        if (!gpname) {
            min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
    }

    if (cred->local) {
        maj = gss_inquire_cred_by_mech(&min, cred->local,
                                       gpp_special_mech(mech_type),
                                       gpname ? &gpname->local : NULL,
                                       initiator_lifetime, acceptor_lifetime,
                                       cred_usage);
    } else if (cred->remote) {
        maj = gpm_inquire_cred_by_mech(&min, cred->remote,
                                       gpp_unspecial_mech(mech_type),
                                       gpname ? &gpname->remote : NULL,
                                       initiator_lifetime, acceptor_lifetime,
                                       cred_usage);
    } else {
        min = 0;
        maj = GSS_S_FAILURE;
    }

done:
    *minor_status = gpp_map_error(min);
    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        gssi_release_cred(&min, (gss_cred_id_t*)&cred);
    }
    if (name && maj == GSS_S_COMPLETE) {
        *name = (gss_name_t)gpname;
    } else {
        free(gpname);
    }
    return maj;
}

OM_uint32 gssi_inquire_cred_by_oid(OM_uint32 *minor_status,
	                           const gss_cred_id_t cred_handle,
	                           const gss_OID desired_object,
	                           gss_buffer_set_t *data_set)
{
    struct gpp_cred_handle *cred = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (cred_handle == GSS_C_NO_CREDENTIAL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    cred = (struct gpp_cred_handle *)cred_handle;

    /* NOTE: For now we can do this only for local credentials,
     * but as far as I know there is no real oid defined, at least
     * for the krb5 mechs, so this may be a mooot point */
    if (!cred->local) {
        return GSS_S_UNAVAILABLE;
    }

    maj = gss_inquire_cred_by_oid(&min, cred->local, desired_object, data_set);

    *minor_status = gpp_map_error(min);
    return maj;
}

#define GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH 11
#define GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x04"

const gss_OID_desc gpp_allowed_enctypes_oid = {
    .length = GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID_LENGTH,
    .elements = GSS_KRB5_SET_ALLOWABLE_ENCTYPES_OID
};

struct gpp_allowable_enctypes {
    uint32_t num_ktypes;
    krb5_enctype *ktypes;
};

#define KRB5_SET_ALLOWED_ENCTYPE "krb5_set_allowed_enctype_values"

static uint32_t gpp_set_opt_allowable_entypes(uint32_t *min, gssx_cred *cred,
                                              const gss_buffer_t value)
{
    struct gpp_allowable_enctypes *ae;
    struct gssx_cred_element *ce = NULL;
    gss_OID_desc mech;

    /* Find the first element that matches one of the krb related OIDs */
    for (unsigned i = 0; i < cred->elements.elements_len; i++) {
        gp_conv_gssx_to_oid(&cred->elements.elements_val[i].mech, &mech);
        if (gpp_is_krb5_oid(&mech)) {
            ce = &cred->elements.elements_val[i];
            break;
        }
    }

    if (!ce) {
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    ae = (struct gpp_allowable_enctypes *)value->value;
    *min = gp_add_option(&ce->options.options_val,
                         &ce->options.options_len,
                         KRB5_SET_ALLOWED_ENCTYPE,
                         sizeof(KRB5_SET_ALLOWED_ENCTYPE),
                         ae->ktypes,
                         sizeof(krb5_enctype) * ae->num_ktypes);
    if (*min != 0) {
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

#define KRB5_SET_NO_CI_FLAGS "krb5_set_no_ci_flags"

static uint32_t gpp_set_no_ci_flags(uint32_t *min, gssx_cred *cred,
                                    const gss_buffer_t value)
{
    struct gssx_cred_element *ce = NULL;
    gss_OID_desc mech;

    /* Find the first element that matches one of the krb related OIDs */
    for (unsigned i = 0; i < cred->elements.elements_len; i++) {
        gp_conv_gssx_to_oid(&cred->elements.elements_val[i].mech, &mech);
        if (gpp_is_krb5_oid(&mech)) {
            ce = &cred->elements.elements_val[i];
            break;
        }
    }

    if (!ce) {
        *min = EINVAL;
        return GSS_S_FAILURE;
    }

    *min = gp_add_option(&ce->options.options_val,
                         &ce->options.options_len,
                         KRB5_SET_NO_CI_FLAGS,
                         sizeof(KRB5_SET_NO_CI_FLAGS),
                         NULL, 0);
    if (*min != 0) {
        return GSS_S_FAILURE;
    }

    return GSS_S_COMPLETE;
}

static uint32_t gpp_remote_options(uint32_t *min, gssx_cred *cred,
                                   const gss_OID desired_object,
                                   const gss_buffer_t value)
{
    uint32_t maj  = GSS_S_UNAVAILABLE;

    if (gss_oid_equal(&gpp_allowed_enctypes_oid, desired_object)) {
        maj = gpp_set_opt_allowable_entypes(min, cred, value);
    } else if (gss_oid_equal(GSS_KRB5_CRED_NO_CI_FLAGS_X, desired_object)) {
        maj = gpp_set_no_ci_flags(min, cred, value);
    }

    return maj;
}

OM_uint32 gssi_set_cred_option(OM_uint32 *minor_status,
                               gss_cred_id_t *cred_handle,
                               const gss_OID desired_object,
                               const gss_buffer_t value)
{
    struct gpp_cred_handle *cred = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (*cred_handle == GSS_C_NO_CREDENTIAL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    cred = (struct gpp_cred_handle *)*cred_handle;

    /* NOTE: For now we can do this only for known objects
     * or local credentials */
    if (cred->remote) {
        return gpp_remote_options(minor_status, cred->remote,
                                  desired_object, value);
    }
    if (!cred->local) {
        return GSS_S_UNAVAILABLE;
    }

    maj = gss_set_cred_option(&min, &cred->local, desired_object, value);

    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_store_cred(OM_uint32 *minor_status,
                          const gss_cred_id_t input_cred_handle,
                          gss_cred_usage_t input_usage,
                          const gss_OID desired_mech,
                          OM_uint32 overwrite_cred,
                          OM_uint32 default_cred,
                          gss_OID_set *elements_stored,
                          gss_cred_usage_t *cred_usage_stored)
{
    return gssi_store_cred_into(minor_status, input_cred_handle, input_usage,
                                desired_mech, overwrite_cred, default_cred,
                                NULL, elements_stored, cred_usage_stored);
}

OM_uint32 gssi_store_cred_into(OM_uint32 *minor_status,
                               const gss_cred_id_t input_cred_handle,
                               gss_cred_usage_t input_usage,
                               const gss_OID desired_mech,
                               OM_uint32 overwrite_cred,
                               OM_uint32 default_cred,
                               gss_const_key_value_set_t cred_store,
                               gss_OID_set *elements_stored,
                               gss_cred_usage_t *cred_usage_stored)
{
    struct gpp_cred_handle *cred = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;
    if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }
    cred = (struct gpp_cred_handle *)input_cred_handle;

    if (cred->remote) {
        maj = gpp_store_remote_creds(&min, default_cred != 0, cred_store,
                                     cred->remote);
        goto done;
    }

    maj = gss_store_cred_into(&min, cred->local, input_usage,
                              gpp_special_mech(desired_mech),
                              overwrite_cred, default_cred, cred_store,
                              elements_stored, cred_usage_stored);
done:
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_release_cred(OM_uint32 *minor_status,
                            gss_cred_id_t *cred_handle)
{
    struct gpp_cred_handle *handle;
    uint32_t tmaj;
    uint32_t tmin;
    uint32_t maj;
    uint32_t min;

    GSSI_TRACE();

    if (cred_handle == NULL) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    handle = (struct gpp_cred_handle *)*cred_handle;

    tmaj = gpm_release_cred(&tmin, &handle->remote);

    maj = gpp_cred_handle_free(&min, handle);
    if (tmaj && maj == GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }

    *cred_handle = GSS_C_NO_CREDENTIAL;
    *minor_status = min;
    return maj;
}

OM_uint32 gssi_export_cred(OM_uint32 *minor_status,
                           gss_cred_id_t cred_handle,
                           gss_buffer_t token)
{
    struct gpp_cred_handle *cred;

    GSSI_TRACE();

    cred = (struct gpp_cred_handle *)cred_handle;
    if (!cred) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* We do not support exporting creds via the proxy.
     * It's exclusively a local operation for now */
    if (!cred->local) {
        return GSS_S_CRED_UNAVAIL;
    }

    return gss_export_cred(minor_status, cred->local, token);
}

OM_uint32 gssi_import_cred(OM_uint32 *minor_status,
                           gss_buffer_t token,
                           gss_cred_id_t *cred_handle)
{
    GSSI_TRACE();
    return GSS_S_UNAVAILABLE;
}

OM_uint32 gssi_import_cred_by_mech(OM_uint32 *minor_status,
                                   gss_OID mech_type,
                                   gss_buffer_t token,
                                   gss_cred_id_t *cred_handle)
{
    struct gpp_cred_handle *cred;
    gss_buffer_desc wrap_token = {0};
    gss_OID spmech;
    OM_uint32 maj, min = 0;
    uint32_t len;

    GSSI_TRACE();

    maj = gpp_cred_handle_init(minor_status, false, NULL, &cred);
    if (maj) {
        return maj;
    }

    /* NOTE: it makes no sense to import a cred remotely atm,
     * so we only handle the local case for now. */
    spmech = gpp_special_mech(mech_type);
    if (spmech == GSS_C_NO_OID) {
        maj = GSS_S_FAILURE;
        goto done;
    }

    wrap_token.length = sizeof(uint32_t) + spmech->length + token->length;
    wrap_token.value = malloc(wrap_token.length);
    if (!wrap_token.value) {
        wrap_token.length = 0;
        maj = GSS_S_FAILURE;
        goto done;
    }

    len = htobe32(wrap_token.length);
    memcpy(wrap_token.value, &len, sizeof(uint32_t));
    memcpy(wrap_token.value + sizeof(uint32_t),
           spmech->elements, spmech->length);
    memcpy(wrap_token.value + sizeof(uint32_t) + spmech->length,
           token->value, token->length);

    maj = gss_import_cred(&min, &wrap_token, &cred->local);

done:
    *minor_status = gpp_map_error(min);
    if (maj == GSS_S_COMPLETE) {
        *cred_handle = (gss_cred_id_t)cred;
    } else {
        free(cred);
    }
    (void)gss_release_buffer(&min, &wrap_token);
    return maj;
}
