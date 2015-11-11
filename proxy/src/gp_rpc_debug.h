/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_RPC_DEBUG_H_
#define _GP_RPC_DEBUG_H_

#include "gp_debug.h"

void gpdbg_utf8string(utf8string *x);
void gpdbg_octet_string(octet_string *x);
void gpdbg_gssx_uint64(gssx_uint64 *x);
#define gpdbg_gssx_qop gpdbg_gssx_uint64
#define gpdbg_gssx_buffer gpdbg_octet_string
void gpdbg_gssx_OID(gssx_OID *x);
void gpdbg_gssx_OID_set(gssx_OID_set *x);
void gpdbg_gssx_cred_usage(gssx_cred_usage *x);
#define gpdbg_gssx_time gpdbg_gssx_uint64
void gpdbg_gssx_option(gssx_option *x);
void gpdbg_gssx_mech_attr(gssx_mech_attr *x);
void gpdbg_gssx_mech_info(gssx_mech_info *x);
void gpdbg_gssx_name_attr(gssx_name_attr *x);
void gpdbg_gssx_status(gssx_status *x);
void gpdbg_gssx_call_ctx(gssx_call_ctx *x);
void gpdbg_gssx_name(gssx_name *x);
void gpdbg_gssx_cred_element(gssx_cred_element *x);
void gpdbg_gssx_cred(gssx_cred *x);
void gpdbg_gssx_ctx(gssx_ctx *x);
void gpdbg_gssx_handle(gssx_handle *x);
void gpdbg_gssx_cb(gssx_cb *x);

void gpdbg_gssx_arg_release_handle(gssx_arg_release_handle *x);
void gpdbg_gssx_res_release_handle(gssx_res_release_handle *x);
void gpdbg_gssx_arg_indicate_mechs(gssx_arg_indicate_mechs *x);
void gpdbg_gssx_res_indicate_mechs(gssx_res_indicate_mechs *x);
void gpdbg_gssx_arg_import_and_canon_name(gssx_arg_import_and_canon_name *x);
void gpdbg_gssx_res_import_and_canon_name(gssx_res_import_and_canon_name *x);
void gpdbg_gssx_arg_get_call_context(gssx_arg_get_call_context *x);
void gpdbg_gssx_res_get_call_context(gssx_res_get_call_context *x);
void gpdbg_gssx_arg_acquire_cred(gssx_arg_acquire_cred *x);
void gpdbg_gssx_res_acquire_cred(gssx_res_acquire_cred *x);
void gpdbg_gssx_arg_export_cred(gssx_arg_export_cred *x);
void gpdbg_gssx_res_export_cred(gssx_res_export_cred *x);
void gpdbg_gssx_arg_import_cred(gssx_arg_import_cred *x);
void gpdbg_gssx_res_import_cred(gssx_res_import_cred *x);
void gpdbg_gssx_arg_store_cred(gssx_arg_store_cred *x);
void gpdbg_gssx_res_store_cred(gssx_res_store_cred *x);
void gpdbg_gssx_arg_init_sec_context(gssx_arg_init_sec_context *x);
void gpdbg_gssx_res_init_sec_context(gssx_res_init_sec_context *x);
void gpdbg_gssx_arg_accept_sec_context(gssx_arg_accept_sec_context *x);
void gpdbg_gssx_res_accept_sec_context(gssx_res_accept_sec_context *x);
void gpdbg_gssx_arg_get_mic(gssx_arg_get_mic *x);
void gpdbg_gssx_res_get_mic(gssx_res_get_mic *x);
void gpdbg_gssx_arg_verify_mic(gssx_arg_verify_mic *x);
void gpdbg_gssx_res_verify_mic(gssx_res_verify_mic *x);
void gpdbg_gssx_arg_wrap(gssx_arg_wrap *x);
void gpdbg_gssx_res_wrap(gssx_res_wrap *x);
void gpdbg_gssx_arg_unwrap(gssx_arg_unwrap *x);
void gpdbg_gssx_res_unwrap(gssx_res_unwrap *x);
void gpdbg_gssx_arg_wrap_size_limit(gssx_arg_wrap_size_limit *x);
void gpdbg_gssx_res_wrap_size_limit(gssx_res_wrap_size_limit *x);

#define GP_RPC_DEBUG_LVL 2
#define GP_RPC_DEBUG_FULL 3

#define GPRPCDEBUG(name, x) do { \
    if (GP_RPC_DEBUG_LVL <= gp_debug) { \
        if (x == NULL) { \
            gp_debug_printf("<Null> "); \
        } else { \
            gpdbg_##name(x); \
        } \
    } \
} while(0)

#endif /* _GP_RPC_DEBUG_H_ */
