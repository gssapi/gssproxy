/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#include "gp_rpc_process.h"
#include <gssapi/gssapi.h>

int gp_wrap_size_limit(struct gp_call_ctx *gpcall UNUSED,
                       union gp_rpc_arg *arg,
                       union gp_rpc_res *res)
{
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    struct gssx_arg_wrap_size_limit *wsla;
    struct gssx_res_wrap_size_limit *wslr;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret;
    int exp_ctx_type;
    OM_uint32 max_size;

    wsla = &arg->wrap_size_limit;
    wslr = &res->wrap_size_limit;

    GPRPCDEBUG(gssx_arg_wrap_size_limit, wsla);

    exp_ctx_type = gp_get_exported_context_type(&wsla->call_ctx);
    if (exp_ctx_type == -1) {
        ret_maj = GSS_S_FAILURE;
        ret_min = EINVAL;
        goto done;
    }

    ret_maj = gp_import_gssx_to_ctx_id(&ret_min, 0,
                                       &wsla->context_handle,
                                       &context_handle);
    if (ret_maj) {
        goto done;
    }

    ret_maj = gss_wrap_size_limit(&ret_min,
                                  context_handle,
                                  wsla->conf_req,
                                  wsla->qop_state,
                                  wsla->req_output_size,
                                  &max_size);
    if (ret_maj) {
        goto done;
    }

    wslr->max_input_size = max_size;

    ret_maj = GSS_S_COMPLETE;
    ret_min = 0;

done:
    ret = gp_conv_status_to_gssx(ret_maj, ret_min,
                                 GSS_C_NO_OID,
                                 &wslr->status);
    GPRPCDEBUG(gssx_res_wrap_size_limit, wslr);
    return ret;
}
