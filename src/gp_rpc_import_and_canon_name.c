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


/* NOTE: Very Important, before ever touching this function please read
 * carefully RFC 2744 section 3.10 "Names".
 * I am not kidding, if you hav not read it, go back and do it now, or do not
 * touch this function */

int gp_import_and_canon_name(struct gssproxy_ctx *gpctx,
                             struct gp_service *gpsvc,
                             union gp_rpc_arg *arg,
                             union gp_rpc_res *res)
{
    struct gssx_arg_import_and_canon_name *icna;
    struct gssx_res_import_and_canon_name *icnr;
    gss_OID mech = GSS_C_NO_OID;
    gss_name_t import_name = GSS_C_NO_NAME;
    gss_name_t output_name = GSS_C_NO_NAME;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    int ret;

    icna = &arg->import_and_canon_name;
    icnr = &res->import_and_canon_name;

    if (icna->input_name.display_name.octet_string_len == 0 &&
        icna->input_name.exported_name.octet_string_len == 0) {
        ret = EINVAL;
        goto done;
    }

    ret_maj = gp_conv_gssx_to_name(&ret_min, &icna->input_name, &import_name);
    if (ret_maj) {
        goto done;
    }

    if (icna->mech.octet_string_len != 0) {

        ret = gp_conv_gssx_to_oid_alloc(&icna->mech, &mech);
        if (ret) {
            ret_maj = GSS_S_FAILURE;
            ret_min = ret;
            goto done;
        }

        ret_maj = gss_canonicalize_name(&ret_min, import_name,
                                        mech, &output_name);
        if (ret_maj) {
            goto done;
        }

        ret_maj = gp_conv_name_to_gssx_alloc(&ret_min,
                                             output_name, &icnr->output_name);
    } else {
        ret_maj = gp_conv_name_to_gssx_alloc(&ret_min,
                                             import_name, &icnr->output_name);
    }

    /* TODO: check also icna->input_name.exported_composite_name */
    /* TODO: icna->name_attributes */

done:
    ret = gp_conv_status_to_gssx(&icna->call_ctx,
                                 ret_maj, ret_min, mech,
                                 &icnr->status);

    gss_release_oid(&ret_min, &mech);
    gss_release_name(&ret_min, &import_name);
    gss_release_name(&ret_min, &output_name);
    return ret;
}
