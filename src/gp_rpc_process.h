/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_RPC_PROCESS_H_
#define _GP_RPC_PROCESS_H_

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include "gp_common.h"
#include "gp_conv.h"
#include "gp_export.h"
#include "rpcgen/gss_proxy.h"
#include "rpcgen/gp_rpc.h"
#include "gp_rpc_creds.h"
#include "gp_rpc_debug.h"

struct gssproxy_ctx;
struct gp_service;

#define gp_exec_std_args struct gp_call_ctx *gpcall, \
                         union gp_rpc_arg *arg, \
                         union gp_rpc_res *res

#define GP_EXEC_UNUSED_FUNC(name)               \
    int name(struct gp_call_ctx *gpcall UNUSED, \
             union gp_rpc_arg *arg UNUSED,      \
             union gp_rpc_res *res UNUSED)      \
    { return 0; }

int gp_indicate_mechs(gp_exec_std_args);
int gp_get_call_context(gp_exec_std_args);
int gp_import_and_canon_name(gp_exec_std_args);
int gp_export_cred(gp_exec_std_args);
int gp_import_cred(gp_exec_std_args);
int gp_acquire_cred(gp_exec_std_args);
int gp_store_cred(gp_exec_std_args);
int gp_init_sec_context(gp_exec_std_args);
int gp_accept_sec_context(gp_exec_std_args);
int gp_release_handle(gp_exec_std_args);
int gp_get_mic(gp_exec_std_args);
int gp_verify_mic(gp_exec_std_args);
int gp_wrap(gp_exec_std_args);
int gp_unwrap(gp_exec_std_args);
int gp_wrap_size_limit(gp_exec_std_args);

#endif /* _GP_RPC_PROCESS_H_ */
