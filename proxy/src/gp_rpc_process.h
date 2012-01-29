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

#ifndef _GP_RPC_PROCESS_H_
#define _GP_RPC_PROCESS_H_

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include "gp_common.h"
#include "gp_conv.h"
#include "gp_export.h"
#include "rpcgen/gss_proxy.h"
#include "rpcgen/gp_rpc.h"

struct gssproxy_ctx;

union gp_rpc_arg {
    gssx_arg_release_handle release_handle;
    gssx_arg_indicate_mechs indicate_mechs;
    gssx_arg_import_and_canon_name import_and_canon_name;
    gssx_arg_get_call_context get_call_context;
    gssx_arg_acquire_cred acquire_cred;
    gssx_arg_export_cred export_cred;
    gssx_arg_import_cred import_cred;
    gssx_arg_store_cred store_cred;
    gssx_arg_init_sec_context init_sec_context;
    gssx_arg_accept_sec_context accept_sec_context;
    gssx_arg_get_mic get_mic;
    gssx_arg_verify_mic verify_mic;
    gssx_arg_wrap wrap;
    gssx_arg_unwrap unwrap;
    gssx_arg_wrap_size_limit wrap_size_limit;
};

union gp_rpc_res {
    gssx_res_release_handle release_handle;
    gssx_res_indicate_mechs indicate_mechs;
    gssx_res_import_and_canon_name import_and_canon_name;
    gssx_res_get_call_context get_call_context;
    gssx_res_acquire_cred acquire_cred;
    gssx_res_export_cred export_cred;
    gssx_res_import_cred import_cred;
    gssx_res_store_cred store_cred;
    gssx_res_init_sec_context init_sec_context;
    gssx_res_accept_sec_context accept_sec_context;
    gssx_res_get_mic get_mic;
    gssx_res_verify_mic verify_mic;
    gssx_res_wrap wrap;
    gssx_res_unwrap unwrap;
    gssx_res_wrap_size_limit wrap_size_limit;
};

#define gp_exec_std_args struct gssproxy_ctx *gpctx, \
                         union gp_rpc_arg *arg, \
                         union gp_rpc_res *res

typedef int (*gp_exec_fn)(gp_exec_std_args);

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
int gp_verify(gp_exec_std_args);
int gp_wrap(gp_exec_std_args);
int gp_unwrap(gp_exec_std_args);
int gp_wrap_size_limit(gp_exec_std_args);

struct gp_rpc_fn_set {
    xdrproc_t arg_fn;
    xdrproc_t res_fn;
    gp_exec_fn exec_fn;
};

#endif /* _GP_RPC_PROCESS_H_ */
