/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_RPC_CREDS_H_
#define _GP_RPC_CREDS_H_

#include "config.h"
#include <stdint.h>
#include <gssapi/gssapi.h>

struct gp_call_ctx;

bool gp_creds_allowed_mech(struct gp_call_ctx *gpcall, gss_OID desired_mech);
uint32_t gp_get_supported_mechs(uint32_t *min, gss_OID_set *set);

struct gssx_arg_acquire_cred;
enum gp_aqcuire_cred_type {
    ACQ_NORMAL = 0,
    ACQ_IMPNAME = 1,
};
int gp_get_acquire_type(struct gssx_arg_acquire_cred *arg);

uint32_t gp_add_krb5_creds(uint32_t *min,
                           struct gp_call_ctx *gpcall,
                           enum gp_aqcuire_cred_type acquire_type,
                           gss_cred_id_t in_cred,
                           gssx_name *desired_name,
                           gss_cred_usage_t cred_usage,
                           uint32_t initiator_time_req,
                           uint32_t acceptor_time_req,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           uint32_t *initiator_time_rec,
                           uint32_t *acceptor_time_rec);

uint32_t gp_cred_allowed(uint32_t *min,
                         struct gp_call_ctx *gpcall,
                         gss_cred_id_t cred,
                         gss_name_t target_name);

void gp_filter_flags(struct gp_call_ctx *gpcall, uint32_t *flags);

struct gp_cred_check_handle {
    struct gp_call_ctx *ctx;
    struct {
        u_int options_len;
        gssx_option *options_val;
    } options;
};
uint32_t gp_check_sync_creds(struct gp_cred_check_handle *h,
                             gss_cred_id_t cred);
uint32_t gp_export_sync_creds(uint32_t *min, struct gp_call_ctx *gpcall,
                              gss_cred_id_t *cred,
                              gssx_option **options_val, u_int *options_len);

#endif /* _GP_RPC_CREDS_H_ */
