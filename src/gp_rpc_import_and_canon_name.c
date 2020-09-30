/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"


/* NOTE: Very Important, before ever touching this function please read
 * carefully RFC 2744 section 3.10 "Names".
 * I am not kidding, if you hav not read it, go back and do it now, or do not
 * touch this function */

int gp_import_and_canon_name(struct gp_call_ctx *gpcall UNUSED,
                             union gp_rpc_arg *arg,
                             union gp_rpc_res *res)
{
    struct gssx_arg_import_and_canon_name *icna;
    struct gssx_res_import_and_canon_name *icnr;
    gss_OID mech = GSS_C_NO_OID;
    gss_name_t import_name = GSS_C_NO_NAME;
    gss_name_t output_name = GSS_C_NO_NAME;
    gss_buffer_desc localname = GSS_C_EMPTY_BUFFER;
    struct gssx_option *val = NULL;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    int ret;

    icna = &arg->import_and_canon_name;
    icnr = &res->import_and_canon_name;

    GPRPCDEBUG(gssx_arg_import_and_canon_name, icna);

    if (icna->input_name.display_name.octet_string_len == 0 &&
        icna->input_name.exported_name.octet_string_len == 0) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
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
    }

    /* We implement gss_localname in this function via a special option */
    gp_options_find(val, icna->options,
                    LOCALNAME_OPTION, sizeof(LOCALNAME_OPTION));
    if (val) {
        ret_maj = gss_localname(&ret_min, import_name, mech, &localname);
        if (ret_maj) {
            goto done;
        }
        ret_min = gp_add_option(&icnr->options.options_val,
                                &icnr->options.options_len,
                                LOCALNAME_OPTION,
                                sizeof(LOCALNAME_OPTION),
                                localname.value,
                                localname.length);
        if (ret_min) {
            ret_maj = GSS_S_FAILURE;
        }

        goto done;
    }

    /* regular import/canon part */
    if (mech != GSS_C_NO_OID) {

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
    ret = gp_conv_status_to_gssx(ret_maj, ret_min, mech,
                                 &icnr->status);
    GPRPCDEBUG(gssx_res_import_and_canon_name, icnr);

    gss_release_oid(&ret_min, &mech);
    gss_release_name(&ret_min, &import_name);
    gss_release_name(&ret_min, &output_name);
    gss_release_buffer(&ret_min, &localname);
    return ret;
}
