/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "rpcgen/gss_proxy.h"
#include "gp_rpc_debug.h"
#include <ctype.h>

void gpdbg_utf8string(utf8string *x)
{
    gp_debug_printf("\"%.*s\" ", (int)x->utf8string_len, x->utf8string_val);
}

void gpdbg_octet_string(octet_string *x)
{
    fprintf(stderr, "[ ");
    if ((GP_RPC_DEBUG_FULL > gp_debug) && (x->octet_string_len > 16)) {
        for (int i = 0; i < 16; i++) {
            char c = x->octet_string_val[i];
            fprintf(stderr, "%c", isalnum(c) ? c : '.');
        }
        fprintf(stderr, "... ] ");
    } else {
        for (unsigned i = 0; i < x->octet_string_len; i++) {
            fprintf(stderr, "%x", x->octet_string_val[i]);
        }
        fprintf(stderr, " ] ");
    }
}

void gpdbg_gssx_uint64(gssx_uint64 *x)
{
    gp_debug_printf("%llu ", (long long unsigned)*x);
}


void gpdbg_gssx_OID(gssx_OID *x)
{
    gss_OID_desc oid = { x->octet_string_len, x->octet_string_val };
    gss_buffer_desc oidbuf;
    uint32_t maj, min;

    if (x->octet_string_len == 0) {
        gp_debug_printf("<None> ");
        return;
    }

    maj = gss_oid_to_str(&min, &oid, &oidbuf);
    if (GSS_ERROR(maj)) {
        gp_debug_printf("<BAD OID> ");
    } else {
        gp_debug_printf("%.*s ", oidbuf.length, (char *)oidbuf.value);
    }
    maj = gss_release_buffer(&min, &oidbuf);
}

void gpdbg_gssx_OID_set(gssx_OID_set *x)
{
    gp_debug_printf("{ ");
    for (unsigned i = 0; i < x->gssx_OID_set_len; i++) {
        gpdbg_gssx_OID(&x->gssx_OID_set_val[i]);
    }
    gp_debug_printf("} ");
}

void gpdbg_gssx_cred_usage(gssx_cred_usage *x)
{
    switch (*x) {
    case GSSX_C_INITIATE:
        gp_debug_printf("INITIATE ");
        break;
    case GSSX_C_ACCEPT:
        gp_debug_printf("ACCEPT ");
        break;
    case GSSX_C_BOTH:
        gp_debug_printf("BOTH ");
        break;
    default:
        gp_debug_printf("<BAD CRED USAGE (%u)> ", (unsigned)*x);
        break;
    }
}

void gpdbg_gssx_option(gssx_option *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_buffer(&x->option);
    gpdbg_gssx_buffer(&x->value);
    gp_debug_printf("} ");
}

#define gpdbg_extensions(x) do { \
    if ((x)->extensions.extensions_len > 0) { \
        gp_debug_printf("[ "); \
        for (unsigned i = 0; i < (x)->extensions.extensions_len; i++) { \
            gpdbg_gssx_option(&(x)->extensions.extensions_val[i]); \
        } \
        gp_debug_printf("] "); \
    } \
} while(0)

#define gpdbg_options(x) do { \
    if ((x)->options.options_len > 0) { \
        gp_debug_printf("[ "); \
        for (unsigned i = 0; i < (x)->options.options_len; i++) { \
            gpdbg_gssx_option(&(x)->options.options_val[i]); \
        } \
        gp_debug_printf("] "); \
    } \
} while(0)

void gpdbg_gssx_mech_attr(gssx_mech_attr *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_OID(&x->attr);
    gpdbg_gssx_buffer(&x->name);
    gpdbg_gssx_buffer(&x->short_desc);
    gpdbg_gssx_buffer(&x->long_desc);
    gpdbg_extensions(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_mech_info(gssx_mech_info *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_OID(&x->mech);
    gpdbg_gssx_OID_set(&x->name_types);
    gpdbg_gssx_OID_set(&x->mech_attrs);
    gpdbg_gssx_OID_set(&x->known_mech_attrs);
    gpdbg_gssx_OID_set(&x->cred_options);
    gpdbg_gssx_OID_set(&x->sec_ctx_options);
    gpdbg_gssx_buffer(&x->saslname_sasl_mech_name);
    gpdbg_gssx_buffer(&x->saslname_mech_name);
    gpdbg_gssx_buffer(&x->saslname_mech_desc);
    gpdbg_extensions(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_name_attr(gssx_name_attr *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_buffer(&x->attr);
    gpdbg_gssx_buffer(&x->value);
    gpdbg_extensions(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_status(gssx_status *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_uint64(&x->major_status);
    gpdbg_gssx_OID(&x->mech);
    gpdbg_gssx_uint64(&x->minor_status);
    gpdbg_utf8string(&x->major_status_string);
    gpdbg_utf8string(&x->minor_status_string);
    gpdbg_octet_string(&x->server_ctx);
    gpdbg_options(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_call_ctx(gssx_call_ctx *x)
{
    gp_debug_printf("{ ");
    gpdbg_utf8string(&x->locale);
    gpdbg_octet_string(&x->server_ctx);
    gpdbg_options(x);
    gp_debug_printf("} ");
}

#define gpdbg_name_attributes(X) do { \
    gp_debug_printf("[ "); \
    if (x->name_attributes.name_attributes_len > 0) { \
        for (unsigned i = 0; i < x->name_attributes.name_attributes_len; i++) { \
            gpdbg_gssx_name_attr( \
                &x->name_attributes.name_attributes_val[i]); \
        } \
    } \
    gp_debug_printf("] "); \
} while(0)

void gpdbg_gssx_name(gssx_name *x)
{
    if (GP_RPC_DEBUG_FULL <= gp_debug) {
        gp_debug_printf("{ ");
    }
    gpdbg_utf8string((utf8string *)&x->display_name);
    if (GP_RPC_DEBUG_FULL <= gp_debug) {
        gpdbg_gssx_OID(&x->name_type);
        gpdbg_gssx_buffer(&x->exported_name);
        gpdbg_gssx_buffer(&x->exported_composite_name);
        gpdbg_name_attributes(x);
        gpdbg_extensions(x);
        gp_debug_printf("} ");
    }
}

void gpdbg_gssx_cred_element(gssx_cred_element *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_name(&x->MN);
    gpdbg_gssx_OID(&x->mech);
    gpdbg_gssx_cred_usage(&x->cred_usage);
    gpdbg_gssx_time(&x->initiator_time_rec);
    gpdbg_gssx_time(&x->acceptor_time_rec);
    gpdbg_options(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_cred(gssx_cred *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_name(&x->desired_name);
    gp_debug_printf("[ ");
    for (unsigned i = 0; i < x->elements.elements_len; i++) {
        gpdbg_gssx_cred_element(&x->elements.elements_val[i]);
    }
    gp_debug_printf("] ");
    gpdbg_octet_string(&x->cred_handle_reference);
    gp_debug_printf("%d } ", (int)x->needs_release);
}

void gpdbg_gssx_ctx(gssx_ctx *x)
{
    gp_debug_printf("{ ");
    gpdbg_octet_string((octet_string *)&x->exported_context_token);
    gpdbg_octet_string(&x->state);
    gp_debug_printf("%d ", (int)x->needs_release);
    gpdbg_gssx_OID(&x->mech);
    gpdbg_gssx_name(&x->src_name);
    gpdbg_gssx_name(&x->targ_name);
    gpdbg_gssx_time(&x->lifetime);
    gpdbg_gssx_uint64(&x->ctx_flags);
    gp_debug_printf("%d ", (int)x->locally_initiated);
    gp_debug_printf("%d ", (int)x->open);
    gpdbg_options(x);
    gp_debug_printf("} ");
}

void gpdbg_gssx_handle(gssx_handle *x)
{
    switch (x->handle_type) {
    case GSSX_C_HANDLE_SEC_CTX:
        gpdbg_gssx_ctx(&x->gssx_handle_u.sec_ctx_info);
        break;
    case GSSX_C_HANDLE_CRED:
        gpdbg_gssx_cred(&x->gssx_handle_u.cred_info);
        break;
    default:
        gp_debug_printf("<BAD HANDLE> ");
        break;
    }
}

void gpdbg_gssx_cb(gssx_cb *x)
{
    gp_debug_printf("{ ");
    gpdbg_gssx_uint64(&x->initiator_addrtype);
    gpdbg_gssx_buffer(&x->initiator_address);
    gpdbg_gssx_uint64(&x->acceptor_addrtype);
    gpdbg_gssx_buffer(&x->acceptor_address);
    gpdbg_gssx_buffer(&x->application_data);
    gp_debug_printf("} ");
}

/* Actual RPCs Start Here */
void gpdbg_gssx_arg_release_handle(gssx_arg_release_handle *x)
{
    gp_debug_printf("    GSSX_ARG_RELEASE_HANDLE( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("cred_handle: ");
    gpdbg_gssx_handle(&x->cred_handle);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_release_handle(gssx_res_release_handle *x)
{
    gp_debug_printf("    GSSX_RES_RELEASE_HANDLE( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_indicate_mechs(gssx_arg_indicate_mechs *x)
{
    gp_debug_printf("    GSSX_ARG_INDICATE_MECHS( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_indicate_mechs(gssx_res_indicate_mechs *x)
{
    gp_debug_printf("    GSSX_RES_INDICATE_MECHS( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("mechs: [ ");
    for (unsigned i = 0; i < x->mechs.mechs_len; i++) {
        gpdbg_gssx_mech_info(&x->mechs.mechs_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("mech_attr_descs: [ ");
    for (unsigned i = 0; i < x->mech_attr_descs.mech_attr_descs_len; i++) {
        gpdbg_gssx_mech_attr(&x->mech_attr_descs.mech_attr_descs_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("supported_extensions: [ ");
    for (unsigned i = 0;
         i < x->supported_extensions.supported_extensions_len; i++) {
        gpdbg_gssx_buffer(
            &x->supported_extensions.supported_extensions_val[i]);
    }
    gp_debug_printf("] ");
    gpdbg_extensions(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_import_and_canon_name(gssx_arg_import_and_canon_name *x)
{
    gp_debug_printf("    GSSX_ARG_IMPORT_AND_CANON_NAME( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("input_name: ");
    gpdbg_gssx_name(&x->input_name);
    gp_debug_printf("mech: ");
    gpdbg_gssx_OID(&x->mech);
    gp_debug_printf("name_attributes: ");
    gpdbg_name_attributes(x);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_import_and_canon_name(gssx_res_import_and_canon_name *x)
{
    gp_debug_printf("    GSSX_RES_IMPORT_AND_CANON_NAME( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("output_name: ");
    GPRPCDEBUG(gssx_name, x->output_name);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_get_call_context(gssx_arg_get_call_context *x)
{
    gp_debug_printf("    GSSX_ARG_GET_CALL_CONTEXT( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_get_call_context(gssx_res_get_call_context *x)
{
    gp_debug_printf("    GSSX_RES_GET_CALL_CONTEXT( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("server_call_ctx: ");
    gpdbg_octet_string(&x->server_call_ctx);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_acquire_cred(gssx_arg_acquire_cred *x)
{
    gp_debug_printf("    GSSX_ARG_ACQUIRE_CRED( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("input_cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->input_cred_handle);
    gp_debug_printf("add_cred: ");
    gp_debug_printf("%d ", (int)x->add_cred_to_input_handle);
    gp_debug_printf("desired_name: ");
    GPRPCDEBUG(gssx_name, x->desired_name);
    gp_debug_printf("time_req: ");
    gpdbg_gssx_time(&x->time_req);
    gp_debug_printf("desired_mechs: ");
    gpdbg_gssx_OID_set(&x->desired_mechs);
    gp_debug_printf("cred_usage: ");
    gpdbg_gssx_cred_usage(&x->cred_usage);
    gp_debug_printf("initiator_time_req: ");
    gpdbg_gssx_time(&x->initiator_time_req);
    gp_debug_printf("acceptor_time_req: ");
    gpdbg_gssx_time(&x->acceptor_time_req);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_acquire_cred(gssx_res_acquire_cred *x)
{
    gp_debug_printf("    GSSX_RES_ACQUIRE_CRED( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("output_cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->output_cred_handle);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_export_cred(gssx_arg_export_cred *x)
{
    gp_debug_printf("    GSSX_ARG_EXPORT_CRED( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("input_cred_handle: ");
    gpdbg_gssx_cred(&x->input_cred_handle);
    gp_debug_printf("cred_usage: ");
    gpdbg_gssx_cred_usage(&x->cred_usage);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_export_cred(gssx_res_export_cred *x)
{
    gp_debug_printf("    GSSX_RES_EXPORT_CRED( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("usage_exported: ");
    gpdbg_gssx_cred_usage(&x->usage_exported);
    gp_debug_printf("exported_handle: ");
    if (x->exported_handle) {
        gpdbg_octet_string(x->exported_handle);
    } else {
        gp_debug_printf("<Null> ");
    }
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_import_cred(gssx_arg_import_cred *x)
{
    gp_debug_printf("    GSSX_ARG_IMPORT_CRED( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("exported_handle: ");
    gpdbg_octet_string(&x->exported_handle);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_import_cred(gssx_res_import_cred *x)
{
    gp_debug_printf("    GSSX_RES_IMPORT_CRED( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("output_cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->output_cred_handle);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_store_cred(gssx_arg_store_cred *x)
{
    gp_debug_printf("    GSSX_ARG_STORE_CRED( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("input_cred_handle: ");
    gpdbg_gssx_cred(&x->input_cred_handle);
    gp_debug_printf("cred_usage: ");
    gpdbg_gssx_cred_usage(&x->cred_usage);
    gp_debug_printf("desired_mech: ");
    gpdbg_gssx_OID(&x->desired_mech);
    gp_debug_printf("overwrite_cred: ");
    gp_debug_printf("%d ", (int)x->overwrite_cred);
    gp_debug_printf("default_cred: ");
    gp_debug_printf("%d ", (int)x->default_cred);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_store_cred(gssx_res_store_cred *x)
{
    gp_debug_printf("    GSSX_RES_STORE_CRED( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("elements_stored: ");
    gpdbg_gssx_OID_set(&x->elements_stored);
    gp_debug_printf("cred_usage_stored: ");
    gpdbg_gssx_cred_usage(&x->cred_usage_stored);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_init_sec_context(gssx_arg_init_sec_context *x)
{
    gp_debug_printf("    GSSX_ARG_INIT_SEC_CONTEXT( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->cred_handle);
    gp_debug_printf("target_name: ");
    GPRPCDEBUG(gssx_name, x->target_name);
    gp_debug_printf("mech_type: ");
    gpdbg_gssx_OID(&x->mech_type);
    gp_debug_printf("req_flags: ");
    gpdbg_gssx_uint64(&x->req_flags);
    gp_debug_printf("time_req: ");
    gpdbg_gssx_time(&x->time_req);
    gp_debug_printf("input_cb: ");
    GPRPCDEBUG(gssx_cb, x->input_cb);
    gp_debug_printf("input_token: ");
    if (x->input_token) {
        gpdbg_octet_string(x->input_token);
    } else {
        gp_debug_printf("<Null> ");
    }
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_init_sec_context(gssx_res_init_sec_context *x)
{
    gp_debug_printf("    GSSX_RES_INIT_SEC_CONTEXT( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("output_token: ");
    if (x->output_token) {
        gpdbg_octet_string(x->output_token);
    } else {
        gp_debug_printf("<Null> ");
    }
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_accept_sec_context(gssx_arg_accept_sec_context *x)
{
    gp_debug_printf("    GSSX_ARG_ACCEPT_SEC_CONTEXT( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->cred_handle);
    gp_debug_printf("input_token: ");
    gpdbg_octet_string(&x->input_token);
    gp_debug_printf("input_cb: ");
    GPRPCDEBUG(gssx_cb, x->input_cb);
    gp_debug_printf("ret_deleg_cred: ");
    gp_debug_printf("%d ", (int)x->ret_deleg_cred);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_accept_sec_context(gssx_res_accept_sec_context *x)
{
    gp_debug_printf("    GSSX_RES_ACCEPT_SEC_CONTEXT( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("output_token: ");
    if (x->output_token) {
        gpdbg_octet_string(x->output_token);
    } else {
        gp_debug_printf("<Null> ");
    }
    gp_debug_printf("delegated_cred_handle: ");
    GPRPCDEBUG(gssx_cred, x->delegated_cred_handle);
    gpdbg_options(x);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_get_mic(gssx_arg_get_mic *x)
{
    gp_debug_printf("    GSSX_ARG_GET_MIC( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    gpdbg_gssx_ctx(&x->context_handle);
    gp_debug_printf("qop_req: ");
    gpdbg_gssx_qop(&x->qop_req);
    gp_debug_printf("message_buffer: ");
    gpdbg_octet_string(&x->message_buffer);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_get_mic(gssx_res_get_mic *x)
{
    gp_debug_printf("    GSSX_RES_GET_MIC( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("token_buffer: ");
    gpdbg_octet_string(&x->token_buffer);
    gp_debug_printf("qop_state: ");
    GPRPCDEBUG(gssx_qop, x->qop_state);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_verify_mic(gssx_arg_verify_mic *x)
{
    gp_debug_printf("    GSSX_ARG_VERIFY_MIC( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    gpdbg_gssx_ctx(&x->context_handle);
    gp_debug_printf("message_buffer: ");
    gpdbg_octet_string(&x->message_buffer);
    gp_debug_printf("token_buffer: ");
    gpdbg_octet_string(&x->token_buffer);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_verify_mic(gssx_res_verify_mic *x)
{
    gp_debug_printf("    GSSX_RES_VERIFY_MIC( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("qop_state: ");
    GPRPCDEBUG(gssx_qop, x->qop_state);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_wrap(gssx_arg_wrap *x)
{
    gp_debug_printf("    GSSX_ARG_WRAP( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    gpdbg_gssx_ctx(&x->context_handle);
    gp_debug_printf("conf_req: ");
    gp_debug_printf("%d ", (int)x->conf_req);
    gp_debug_printf("message_buffer: [ ");
    for (unsigned i = 0; i < x->message_buffer.message_buffer_len; i++) {
        gpdbg_octet_string(&x->message_buffer.message_buffer_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("qop_state: ");
    gpdbg_gssx_qop(&x->qop_state);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_wrap(gssx_res_wrap *x)
{
    gp_debug_printf("    GSSX_RES_WRAP( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("token_buffer: [ ");
    for (unsigned i = 0; i < x->token_buffer.token_buffer_len; i++) {
        gpdbg_octet_string(&x->token_buffer.token_buffer_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("conf_state: ");
    if (x->conf_state) {
        gp_debug_printf("%d ", (int)*(x->conf_state));
    } else {
        gp_debug_printf("<Null> ");
    }
    gp_debug_printf("qop_state: ");
    GPRPCDEBUG(gssx_qop, x->qop_state);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_arg_unwrap(gssx_arg_unwrap *x)
{
    gp_debug_printf("    GSSX_ARG_UNWRAP( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    gpdbg_gssx_ctx(&x->context_handle);
    gp_debug_printf("token_buffer: [ ");
    for (unsigned i = 0; i < x->token_buffer.token_buffer_len; i++) {
        gpdbg_octet_string(&x->token_buffer.token_buffer_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("qop_state: ");
    gpdbg_gssx_qop(&x->qop_state);
    gp_debug_printf(")\n");
}

void gpdbg_gssx_res_unwrap(gssx_res_unwrap *x)
{
    gp_debug_printf("    GSSX_RES_UNWRAP( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("context_handle: ");
    GPRPCDEBUG(gssx_ctx, x->context_handle);
    gp_debug_printf("message_buffer: [ ");
    for (unsigned i = 0; i < x->message_buffer.message_buffer_len; i++) {
        gpdbg_octet_string(&x->message_buffer.message_buffer_val[i]);
    }
    gp_debug_printf("] ");
    gp_debug_printf("conf_state: ");
    if (x->conf_state) {
        gp_debug_printf("%d ", (int)*(x->conf_state));
    } else {
        gp_debug_printf("<Null> ");
    }
    gp_debug_printf("qop_state: ");
    GPRPCDEBUG(gssx_qop, x->qop_state);
}

void gpdbg_gssx_arg_wrap_size_limit(gssx_arg_wrap_size_limit *x)
{
    gp_debug_printf("    GSSX_ARG_WRAP_SIZE_LIMIT( call_ctx: ");
    gpdbg_gssx_call_ctx(&x->call_ctx);
    gp_debug_printf("context_handle: ");
    gpdbg_gssx_ctx(&x->context_handle);
    gp_debug_printf("conf_req: ");
    gp_debug_printf("%d ", (int)x->conf_req);
    gp_debug_printf("qop_state: ");
    gpdbg_gssx_qop(&x->qop_state);
    gp_debug_printf("req_output_size: ");
    gpdbg_gssx_uint64(&x->req_output_size);
}

void gpdbg_gssx_res_wrap_size_limit(gssx_res_wrap_size_limit *x)
{
    gp_debug_printf("    GSSX_RES_WRAP_SIZE_LIMIT( status: ");
    gpdbg_gssx_status(&x->status);
    gp_debug_printf("max_input_size: ");
    gpdbg_gssx_uint64(&x->max_input_size);
}
