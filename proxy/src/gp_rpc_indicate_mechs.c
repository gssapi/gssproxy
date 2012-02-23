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

#include "gp_rpc_process.h"
#include "gp_debug.h"

int gp_indicate_mechs(struct gssproxy_ctx *gpctx,
                      struct gp_service *gpsvc,
                      union gp_rpc_arg *arg,
                      union gp_rpc_res *res)
{
    struct gssx_arg_indicate_mechs *ima;
    struct gssx_res_indicate_mechs *imr;
    gss_OID_set mech_set = GSS_C_NO_OID_SET;
    gss_OID_set name_types = GSS_C_NO_OID_SET;
    gss_OID_set mech_attrs = GSS_C_NO_OID_SET;
    gss_OID_set known_mech_attrs = GSS_C_NO_OID_SET;
    gss_buffer_desc sasl_mech_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mech_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mech_desc = GSS_C_EMPTY_BUFFER;
    gss_OID_set attr_set = GSS_C_NO_OID_SET;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc short_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc long_desc = GSS_C_EMPTY_BUFFER;
    gssx_mech_info *mi;
    gssx_mech_attr *ma;
    uint32_t ret_maj;
    uint32_t ret_min;
    int present;
    int h, i, j;
    int ret;

    ima = &arg->indicate_mechs;
    imr = &res->indicate_mechs;

    /* get all mechs */
    ret_maj = gss_indicate_mechs(&ret_min, &mech_set);
    if (ret_maj) {
        goto done;
    }

    ret_maj = gss_create_empty_oid_set(&ret_min, &attr_set);
    if (ret_maj) {
        goto done;
    }
    /* fill up gssx_mech_info */

    imr->mechs.mechs_val = calloc(mech_set->count, sizeof(gssx_mech_info));
    if (!imr->mechs.mechs_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    imr->mechs.mechs_len = mech_set->count;

    for (i = 0, h = 0; i < mech_set->count; i++, h++) {

        mi = &imr->mechs.mechs_val[h];

        ret = gp_conv_oid_to_gssx(&mech_set->elements[i], &mi->mech);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        ret_maj = gss_inquire_names_for_mech(&ret_min,
                                             &mech_set->elements[i],
                                             &name_types);
        if (ret_maj) {
            gp_log_failure(&mech_set->elements[i], ret_maj, ret_min);

            /* temporarily skip any offender */
            imr->mechs.mechs_len--;
            h--;
            xdr_free((xdrproc_t)xdr_gssx_OID, (char *)&mi->mech);
            continue;
#if 0
            ret_maj = GSS_S_FAILURE;
            ret_min = EINVAL;
            goto done;
#endif
        }

        ret = gp_conv_oid_set_to_gssx(name_types, &mi->name_types);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_oid_set(&ret_min, &name_types);

        ret_maj = gss_inquire_attrs_for_mech(&ret_min,
                                             &mech_set->elements[i],
                                             &mech_attrs,
                                             &known_mech_attrs);
        if (ret_maj) {
            goto done;
        }

        ret = gp_conv_oid_set_to_gssx(mech_attrs, &mi->mech_attrs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        for (j = 0; j < mech_attrs->count; j++) {

            ret_maj = gss_test_oid_set_member(&ret_min,
                                              &mech_attrs->elements[j],
                                              attr_set,
                                              &present);
            if (ret_maj) {
                goto done;
            }

            if (present) {
                continue;
            }

            ret_maj = gss_add_oid_set_member(&ret_min,
                                             &mech_attrs->elements[j],
                                             &attr_set);
            if (ret_maj) {
                goto done;
            }

        }
        gss_release_oid_set(&ret_min, &mech_attrs);

        ret = gp_conv_oid_set_to_gssx(known_mech_attrs,
                                      &mi->known_mech_attrs);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        for (j = 0; j < known_mech_attrs->count; j++) {

            ret_maj = gss_test_oid_set_member(&ret_min,
                                              &known_mech_attrs->elements[j],
                                              attr_set,
                                              &present);
            if (ret_maj) {
                goto done;
            }

            if (present) {
                continue;
            }

            ret_maj = gss_add_oid_set_member(&ret_min,
                                             &known_mech_attrs->elements[j],
                                             &attr_set);
            if (ret_maj) {
                goto done;
            }

        }
        gss_release_oid_set(&ret_min, &known_mech_attrs);

        ret_maj = gss_inquire_saslname_for_mech(&ret_min,
                                                &mech_set->elements[i],
                                                &sasl_mech_name,
                                                &mech_name,
                                                &mech_desc);
        if (ret_maj) {
            goto done;
        }

        ret = gp_conv_buffer_to_gssx(&sasl_mech_name, &mi->saslname_sasl_mech_name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &sasl_mech_name);

        ret = gp_conv_buffer_to_gssx(&mech_name, &mi->saslname_mech_name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &mech_name);

        ret = gp_conv_buffer_to_gssx(&mech_desc, &mi->saslname_mech_desc);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &mech_desc);
    }

    /* fill up gssx_mech_attr */

    imr->mech_attr_descs.mech_attr_descs_val = calloc(attr_set->count,
                                                      sizeof(gssx_mech_attr));
    if (!imr->mech_attr_descs.mech_attr_descs_val) {
        ret_maj = GSS_S_FAILURE;
        ret_min = ENOMEM;
        goto done;
    }
    imr->mech_attr_descs.mech_attr_descs_len = attr_set->count;

    for (i = 0; i < attr_set->count; i++) {

        ma = &imr->mech_attr_descs.mech_attr_descs_val[i];

        ret = gp_conv_oid_to_gssx(&attr_set->elements[i], &ma->attr);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        ret_maj = gss_display_mech_attr(&ret_min,
                                        &attr_set->elements[i],
                                        &name,
                                        &short_desc,
                                        &long_desc);
        if (ret_maj) {
            goto done;
        }

        ret = gp_conv_buffer_to_gssx(&name, &ma->name);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &name);

        ret = gp_conv_buffer_to_gssx(&short_desc, &ma->short_desc);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &short_desc);

        ret = gp_conv_buffer_to_gssx(&long_desc, &ma->long_desc);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }
        gss_release_buffer(&ret_min, &long_desc);
    }

done:
    ret = gp_conv_status_to_gssx(&ima->call_ctx,
                                 ret_maj, ret_min, GSS_C_NO_OID,
                                 &imr->status);

    gss_release_buffer(&ret_min, &long_desc);
    gss_release_buffer(&ret_min, &short_desc);
    gss_release_buffer(&ret_min, &name);
    gss_release_oid_set(&ret_min, &attr_set);
    gss_release_buffer(&ret_min, &mech_desc);
    gss_release_buffer(&ret_min, &mech_name);
    gss_release_buffer(&ret_min, &sasl_mech_name);
    gss_release_oid_set(&ret_min, &known_mech_attrs);
    gss_release_oid_set(&ret_min, &mech_attrs);
    gss_release_oid_set(&ret_min, &name_types);
    gss_release_oid_set(&ret_min, &mech_set);
    return ret;
}
