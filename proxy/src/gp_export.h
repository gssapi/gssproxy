/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

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
