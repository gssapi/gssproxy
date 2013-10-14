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
#include <string.h>
#include <gssapi/gssapi.h>
#include "gp_common.h"
#include "gp_conv.h"
#include "gp_export.h"
#include "rpcgen/gss_proxy.h"
#include "rpcgen/gp_rpc.h"
#include "gp_rpc_creds.h"

struct gssproxy_ctx;
struct gp_service;

#define gp_exec_std_args struct gp_call_ctx *gpcall, \
                         union gp_rpc_arg *arg, \
                         union gp_rpc_res *res

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
