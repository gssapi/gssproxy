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

#ifndef _GSS_EXPORT_H_
#define _GSS_EXPORT_H_

#include <gssapi/gssapi.h>
#include "rpcgen/gss_proxy.h"

struct gp_call_ctx;

uint32_t gp_export_gssx_cred(uint32_t *min, struct gp_call_ctx *gpcall,
                             gss_cred_id_t *in, gssx_cred *out);
uint32_t gp_import_gssx_cred(uint32_t *min, struct gp_call_ctx *gpcall,
                             gssx_cred *cred, gss_cred_id_t *out);

int gp_get_exported_context_type(struct gssx_call_ctx *ctx);
int gp_get_continue_needed_type(void);
uint32_t gp_export_ctx_id_to_gssx(uint32_t *min, int type, gss_OID mech,
                                  gss_ctx_id_t *in, gssx_ctx *out);
uint32_t gp_import_gssx_to_ctx_id(uint32_t *min, int type,
                                  gssx_ctx *in, gss_ctx_id_t *out);

int gp_get_export_creds_type(struct gssx_call_ctx *ctx);
uint32_t gp_export_creds_to_gssx_options(uint32_t *min, int type,
                                         gss_name_t src_name,
                                         gss_const_OID mech_type,
                                         unsigned int *opt_num,
                                         gssx_option **opt_array);

#endif /* _GSS_EXPORT_H_ */
