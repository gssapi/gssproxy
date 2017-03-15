/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gssapi_gpm.h"
#include <pthread.h>

struct gpm_mech_info {
    gss_OID mech;
    gss_OID_set name_types;
    gss_OID_set mech_attrs;
    gss_OID_set known_mech_attrs;
    gss_OID_set cred_options;
    gss_OID_set sec_ctx_options;
    gss_buffer_t saslname_sasl_mech_name;
    gss_buffer_t saslname_mech_name;
    gss_buffer_t saslname_mech_desc;
};

struct gpm_mech_attr {
    gss_OID attr;
    gss_buffer_t name;
    gss_buffer_t short_desc;
    gss_buffer_t long_desc;
};

struct gpm_mechs {
    bool initialized;

    gss_OID_set mech_set;

    size_t info_len;
    struct gpm_mech_info *info;

    size_t desc_len;
    struct gpm_mech_attr *desc;
};

pthread_mutex_t global_mechs_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_once_t indicate_mechs_once = PTHREAD_ONCE_INIT;
struct gpm_mechs global_mechs = {
    .initialized = false,
    .mech_set = GSS_C_NO_OID_SET,
    .info_len = 0,
    .info = NULL,
    .desc_len = 0,
    .desc = NULL,
};

static uint32_t gpm_copy_gss_OID_set(uint32_t *minor_status,
                                     gss_OID_set oldset, gss_OID_set *newset)
{
    gss_OID_set n;
    uint32_t ret_maj;
    uint32_t ret_min;

    ret_maj = gss_create_empty_oid_set(&ret_min, &n);
    if (ret_maj) {
        *minor_status = ret_min;
        return ret_maj;
    }

    for (size_t i = 0; i < oldset->count; i++) {
        ret_maj = gss_add_oid_set_member(&ret_min, &oldset->elements[i], &n);
        if (ret_maj) {
            *minor_status = ret_min;
            gss_release_oid_set(&ret_min, &n);
            return ret_maj;
        }
    }

    *newset = n;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

static uint32_t gpm_copy_gss_buffer(uint32_t *minor_status,
                                    gss_buffer_t oldbuf,
                                    gss_buffer_t newbuf)
{
    if (!oldbuf || oldbuf->length == 0) {
        newbuf->value = NULL;
        newbuf->length = 0;
        *minor_status = 0;
        return GSS_S_COMPLETE;
    }

    newbuf->value = malloc(oldbuf->length);
    if (!newbuf->value) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(newbuf->value, oldbuf->value, oldbuf->length);
    newbuf->length = oldbuf->length;

    *minor_status = 0;
    return GSS_S_COMPLETE;
}

static bool gpm_equal_oids(gss_const_OID a, gss_const_OID b)
{
    int ret;

    if (a->length == b->length) {
        ret = memcmp(a->elements, b->elements, a->length);
        if (ret == 0) {
            return true;
        }
    }

    return false;
}

static void gpmint_indicate_mechs(void)
{
    union gp_rpc_arg uarg;
    union gp_rpc_res ures;
    gssx_arg_indicate_mechs *arg = &uarg.indicate_mechs;
    gssx_res_indicate_mechs *res = &ures.indicate_mechs;
    struct gpm_mech_info *gi;
    struct gpm_mech_attr *ga;
    gssx_mech_info *mi;
    gssx_mech_attr *ma;
    uint32_t discard;
    uint32_t ret_min;
    uint32_t ret_maj = 0;
    int ret = 0;

    memset(arg, 0, sizeof(gssx_arg_indicate_mechs));
    memset(res, 0, sizeof(gssx_res_indicate_mechs));

    /* ignore call_ctx for now */

    /* execute proxy request */
    ret = gpm_make_call(GSSX_INDICATE_MECHS, &uarg, &ures);
    if (ret) {
        goto done;
    }

    if (res->status.major_status) {
        gpm_save_status(&res->status);
        ret_min = res->status.minor_status;
        ret_maj = res->status.major_status;
        ret = 0;
        goto done;
    }

    ret_maj = gss_create_empty_oid_set(&ret_min, &global_mechs.mech_set);
    if (ret_maj) {
        goto done;
    }

    global_mechs.info = calloc(res->mechs.mechs_len,
                               sizeof(struct gpm_mech_info));
    if (!global_mechs.info) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }

    for (unsigned i = 0; i < res->mechs.mechs_len; i++) {
        mi = &res->mechs.mechs_val[i];
        gi = &global_mechs.info[i];

        ret = gp_conv_gssx_to_oid_alloc(&mi->mech,
                                        &gi->mech);
        if (ret) {
            goto done;
        }
        ret_maj = gss_add_oid_set_member(&ret_min, gi->mech,
                                         &global_mechs.mech_set);
        if (ret_maj) {
            goto done;
        }

        ret = gp_conv_gssx_to_oid_set(&mi->name_types,
                                      &gi->name_types);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_oid_set(&mi->mech_attrs,
                                      &gi->mech_attrs);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_oid_set(&mi->known_mech_attrs,
                                      &gi->known_mech_attrs);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_oid_set(&mi->cred_options,
                                      &gi->cred_options);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_oid_set(&mi->sec_ctx_options,
                                      &gi->sec_ctx_options);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&mi->saslname_sasl_mech_name,
                                           &gi->saslname_sasl_mech_name);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&mi->saslname_mech_name,
                                           &gi->saslname_mech_name);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&mi->saslname_mech_desc,
                                           &gi->saslname_mech_desc);
        if (ret) {
            goto done;
        }
    }
    global_mechs.info_len = res->mechs.mechs_len;

    global_mechs.desc = calloc(res->mech_attr_descs.mech_attr_descs_len,
                               sizeof(struct gpm_mech_attr));
    if (!global_mechs.desc) {
        goto done;
    }

    for (unsigned i = 0; i < res->mech_attr_descs.mech_attr_descs_len; i++) {
        ma = &res->mech_attr_descs.mech_attr_descs_val[i];
        ga = &global_mechs.desc[i];

        ret = gp_conv_gssx_to_oid_alloc(&ma->attr, &ga->attr);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&ma->name, &ga->name);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&ma->short_desc, &ga->short_desc);
        if (ret) {
            goto done;
        }
        ret = gp_conv_gssx_to_buffer_alloc(&ma->long_desc, &ga->long_desc);
        if (ret) {
            goto done;
        }
    }
    global_mechs.desc_len = res->mech_attr_descs.mech_attr_descs_len;

    global_mechs.initialized = true;

done:
    if (ret || ret_maj) {
        for (unsigned i = 0; i < global_mechs.desc_len; i++) {
            ga = &global_mechs.desc[i];
            gss_release_oid(&discard, &ga->attr);
            gss_release_buffer(&discard, ga->name);
            gss_release_buffer(&discard, ga->short_desc);
            gss_release_buffer(&discard, ga->long_desc);
        }
        free(global_mechs.desc);
        global_mechs.desc = NULL;
        for (unsigned i = 0; i < global_mechs.info_len; i++) {
            gi = &global_mechs.info[i];
            gss_release_oid(&discard, &gi->mech);
            gss_release_oid_set(&discard, &gi->name_types);
            gss_release_oid_set(&discard, &gi->mech_attrs);
            gss_release_oid_set(&discard, &gi->known_mech_attrs);
            gss_release_oid_set(&discard, &gi->cred_options);
            gss_release_oid_set(&discard, &gi->sec_ctx_options);
            gss_release_buffer(&discard, gi->saslname_sasl_mech_name);
            gss_release_buffer(&discard, gi->saslname_mech_name);
            gss_release_buffer(&discard, gi->saslname_mech_desc);
        }
        free(global_mechs.info);
        global_mechs.info = NULL;
        gss_release_oid_set(&discard, &global_mechs.mech_set);
    }
    gpm_free_xdrs(GSSX_INDICATE_MECHS, &uarg, &ures);
}

static int gpmint_init_global_mechs(void)
{
    pthread_once(&indicate_mechs_once, gpmint_indicate_mechs);

    if (!global_mechs.initialized) {
        /* this is quite a corner case. It means the pthread_once() call
         * failed for some reason. In this case we need to use a mutex */

        pthread_mutex_lock(&global_mechs_lock);
        /* need to recheck once we acquired the lock, to avoid redoing
         * if we were stuck after another thread that already did it */
        if (!global_mechs.initialized) {
            gpmint_indicate_mechs();
        }
        pthread_mutex_unlock(&global_mechs_lock);

        if (!global_mechs.initialized) {
            /* if still it is not initialized, give up */
            return EIO;
        }
    }

    return 0;
}

OM_uint32 gpm_indicate_mechs(OM_uint32 *minor_status, gss_OID_set *mech_set)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    int ret;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!mech_set) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret= gpmint_init_global_mechs();
    if (ret) {
        *minor_status = ret;
        return GSS_S_FAILURE;
    }

    ret_maj = gpm_copy_gss_OID_set(&ret_min,
                                   global_mechs.mech_set,
                                   mech_set);
    *minor_status = ret_min;
    return ret_maj;
}

OM_uint32 gpm_inquire_names_for_mech(OM_uint32 *minor_status,
                                     gss_OID mech_type,
                                     gss_OID_set *mech_names)
{
    uint32_t ret_min;
    uint32_t ret_maj;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!mech_names) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    for (unsigned i = 0; i < global_mechs.info_len; i++) {
        if (!gpm_equal_oids(global_mechs.info[i].mech, mech_type)) {
            continue;
        }
        ret_maj = gpm_copy_gss_OID_set(&ret_min,
                                       global_mechs.info[i].name_types,
                                       mech_names);
        *minor_status = ret_min;
        return ret_maj;
    }

    *minor_status = 0;
    return GSS_S_BAD_MECH;
}

OM_uint32 gpm_inquire_mechs_for_name(OM_uint32 *minor_status,
                                     gssx_name *input_name,
                                     gss_OID_set *mech_types)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    uint32_t discard;
    gss_OID name_type = GSS_C_NO_OID;
    int present;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!input_name || !mech_types) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    ret_min = gp_conv_gssx_to_oid_alloc(&input_name->name_type, &name_type);
    if (ret_min) {
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret_maj = gss_create_empty_oid_set(&ret_min, mech_types);
    if (ret_maj) {
        goto done;
    }

    for (unsigned i = 0; i < global_mechs.info_len; i++) {
        ret_maj = gss_test_oid_set_member(&ret_min, name_type,
                                          global_mechs.info[i].name_types,
                                          &present);
        if (ret_maj) {
            /* skip on error */
            continue;
        }
        if (present) {
            ret_maj = gss_add_oid_set_member(&ret_min,
                                             global_mechs.info[i].mech,
                                             mech_types);
        }
        if (ret_maj) {
            goto done;
        }
    }

done:
    gss_release_oid(&discard, &name_type);
    if (ret_maj) {
        gss_release_oid_set(&discard, mech_types);
        *minor_status = ret_min;
        return ret_maj;
    }
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 gpm_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                     gss_OID mech,
                                     gss_OID_set *mech_attrs,
                                     gss_OID_set *known_mech_attrs)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    uint32_t discard;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    for (unsigned i = 0; i < global_mechs.info_len; i++) {
        if (!gpm_equal_oids(global_mechs.info[i].mech, mech)) {
            continue;
        }

        if (mech_attrs != NULL) {
            ret_maj = gpm_copy_gss_OID_set(&ret_min,
                                           global_mechs.info[i].mech_attrs,
                                           mech_attrs);
            if (ret_maj) {
                *minor_status = ret_min;
                return ret_maj;
            }
        }

        if (known_mech_attrs != NULL) {
            ret_maj = gpm_copy_gss_OID_set(&ret_min,
                                           global_mechs.info[i].known_mech_attrs,
                                           known_mech_attrs);
            if (ret_maj) {
                gss_release_oid_set(&discard, known_mech_attrs);
            }
            *minor_status = ret_min;
            return ret_maj;
        }

        /* all requested attributes copied successfully */
        *minor_status = 0;
        return GSS_S_COMPLETE;
    }

    *minor_status = 0;
    return GSS_S_BAD_MECH;
}

OM_uint32 gpm_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                        const gss_OID desired_mech,
                                        gss_buffer_t sasl_mech_name,
                                        gss_buffer_t mech_name,
                                        gss_buffer_t mech_description)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    uint32_t discard;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!sasl_mech_name || !mech_name || !mech_description) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    for (unsigned i = 0; i < global_mechs.info_len; i++) {
        if (!gpm_equal_oids(global_mechs.info[i].mech, desired_mech)) {
            continue;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                global_mechs.info[i].saslname_sasl_mech_name,
                                sasl_mech_name);
        if (ret_maj) {
            *minor_status = ret_min;
            return ret_maj;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                global_mechs.info[i].saslname_mech_name,
                                mech_name);
        if (ret_maj) {
            gss_release_buffer(&discard, sasl_mech_name);
            *minor_status = ret_min;
            return ret_maj;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                global_mechs.info[i].saslname_mech_desc,
                                mech_description);
        if (ret_maj) {
            gss_release_buffer(&discard, sasl_mech_name);
            gss_release_buffer(&discard, mech_name);
        }
        *minor_status = ret_min;
        return ret_maj;
    }

    *minor_status = 0;
    return GSS_S_BAD_MECH;
}

OM_uint32 gpm_display_mech_attr(OM_uint32 *minor_status,
                                gss_const_OID mech_attr,
                                gss_buffer_t name,
                                gss_buffer_t short_desc,
                                gss_buffer_t long_desc)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    uint32_t discard;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!name || !short_desc || !long_desc) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    for (unsigned i = 0; i < global_mechs.desc_len; i++) {
        if (!gpm_equal_oids(global_mechs.desc[i].attr, mech_attr)) {
            continue;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                      global_mechs.desc[i].name,
                                      name);
        if (ret_maj) {
            *minor_status = ret_min;
            return ret_maj;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                      global_mechs.desc[i].short_desc,
                                      short_desc);
        if (ret_maj) {
            gss_release_buffer(&discard, name);
            *minor_status = ret_min;
            return ret_maj;
        }
        ret_maj = gpm_copy_gss_buffer(&ret_min,
                                      global_mechs.desc[i].long_desc,
                                      long_desc);
        if (ret_maj) {
            gss_release_buffer(&discard, name);
            gss_release_buffer(&discard, short_desc);
        }
        *minor_status = ret_min;
        return ret_maj;
    }

    *minor_status = 0;
    return GSS_S_BAD_MECH;
}

OM_uint32 gpm_indicate_mechs_by_attrs(OM_uint32 *minor_status,
                                      gss_const_OID_set desired_mech_attrs,
                                      gss_const_OID_set except_mech_attrs,
                                      gss_const_OID_set critical_mech_attrs,
                                      gss_OID_set *mechs)
{
    uint32_t ret_min;
    uint32_t ret_maj;
    uint32_t discard;
    int present;

    if (!minor_status) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }
    if (!mechs) {
        *minor_status = 0;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    ret_min = gpmint_init_global_mechs();
    if (ret_min) {
        *minor_status = ret_min;
        return GSS_S_FAILURE;
    }

    ret_maj = gss_create_empty_oid_set(&ret_min, mechs);
    if (ret_maj) {
        *minor_status = ret_min;
        return ret_maj;
    }

    for (unsigned i = 0; i < global_mechs.info_len; i++) {
        if (desired_mech_attrs != GSS_C_NO_OID_SET) {
            unsigned j;
            for (j = 0; j < desired_mech_attrs->count; j++) {
                ret_maj = gss_test_oid_set_member(&ret_min,
                                            &desired_mech_attrs->elements[j],
                                            global_mechs.info[i].mech_attrs,
                                            &present);
                if (ret_maj) {
                    /* skip in case of errors */
                    break;
                }
                if (!present) {
                    break;
                }
            }
            /* if not desired skip */
            if (j != desired_mech_attrs->count) {
                continue;
            }
        }
        if (except_mech_attrs != GSS_C_NO_OID_SET) {
            unsigned j;
            for (j = 0; j < except_mech_attrs->count; j++) {
                ret_maj = gss_test_oid_set_member(&ret_min,
                                            &except_mech_attrs->elements[j],
                                            global_mechs.info[i].mech_attrs,
                                            &present);
                if (ret_maj) {
                    /* continue in case of errors */
                    continue;
                }
                if (present) {
                    break;
                }
            }
            /* if excepted skip */
            if (j == except_mech_attrs->count) {
                continue;
            }
        }
        if (critical_mech_attrs != GSS_C_NO_OID_SET) {
            unsigned j;
            for (j = 0; j < critical_mech_attrs->count; j++) {
                ret_maj = gss_test_oid_set_member(&ret_min,
                                    &critical_mech_attrs->elements[j],
                                    global_mechs.info[i].known_mech_attrs,
                                    &present);
                if (ret_maj) {
                    /* skip in case of errors */
                    break;
                }
                if (!present) {
                    break;
                }
            }
            /* if not known skip */
            if (j != critical_mech_attrs->count) {
                continue;
            }
        }

        /* passes all tests, add to list */
        ret_maj = gss_add_oid_set_member(&ret_min,
                                         global_mechs.info[i].mech, mechs);
        if (ret_maj) {
            goto done;
        }
    }

done:
    if (ret_maj) {
        gss_release_oid_set(&discard, mechs);
        *minor_status = ret_min;
        return ret_maj;
    }
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
