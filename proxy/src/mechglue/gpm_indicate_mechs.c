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

struct gpm_mechs global_mechs = {
    .initialized = false,
    .mech_set = GSS_C_NO_OID_SET,
    .info_len = 0,
    .info = NULL,
    .desc_len = 0,
    .desc = NULL,
};

pthread_mutex_t global_mechs_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_once_t indicate_mechs_once = PTHREAD_ONCE_INIT;


static uint32_t gpm_copy_gss_OID_set(uint32_t *minor_status,
                                     gss_OID_set oldset, gss_OID_set *newset)
{
    gss_OID_set n;
    uint32_t ret_maj;
    uint32_t ret_min;
    int i;

    ret_maj = gss_create_empty_oid_set(&ret_min, &n);
    if (ret_maj) {
        *minor_status = ret_min;
        return ret_maj;
    }

    for (i = 0; i < oldset->count; i++) {
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
    int i;

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

    for (i = 0; i < res->mechs.mechs_len; i++) {
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

    for (i = 0; i < res->mech_attr_descs.mech_attr_descs_len; i++) {
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
        for (i = 0; i < global_mechs.desc_len; i++) {
            ga = &global_mechs.desc[i];
            gss_release_oid(&discard, &ga->attr);
            gss_release_buffer(&discard, ga->name);
            gss_release_buffer(&discard, ga->short_desc);
            gss_release_buffer(&discard, ga->long_desc);
        }
        free(global_mechs.desc);
        global_mechs.desc = NULL;
        for (i = 0; i < global_mechs.info_len; i++) {
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

OM_uint32 gpm_indicate_mechs(OM_uint32 *minor_status, gss_OID_set *mech_set)
{
    gss_OID_set new_mech_set;
    uint32_t ret_min;
    uint32_t ret_maj;

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
            *minor_status = EIO;
            return GSS_S_FAILURE;
        }
    }

    ret_maj = gpm_copy_gss_OID_set(&ret_min,
                                   global_mechs.mech_set,
                                   &new_mech_set);
    if (ret_maj) {
        *minor_status = ret_min;
        return ret_maj;
    }

    *mech_set = new_mech_set;
    *minor_status = 0;
    return GSS_S_COMPLETE;
}
