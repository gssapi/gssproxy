/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GSSAPI_GPM_H_
#define _GSSAPI_GPM_H_

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "rpcgen/gp_rpc.h"
#include "rpcgen/gss_proxy.h"
#include "src/gp_common.h"
#include "src/gp_conv.h"

int gpm_make_call(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res);
void gpm_free_xdrs(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res);

OM_uint32 gpm_release_name(OM_uint32 *minor_status,
                           gssx_name **input_name);
OM_uint32 gpm_release_buffer(OM_uint32 *minor_status,
                             gss_buffer_t buffer);

void gpm_display_status_init_once(void);
void gpm_save_status(gssx_status *status);
void gpm_save_internal_status(uint32_t err, char *err_str);

OM_uint32 gpm_display_status(OM_uint32 *minor_status,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string);

OM_uint32 gpm_accept_sec_context(OM_uint32 *minor_status,
                                 gssx_ctx **context_handle,
                                 gssx_cred *acceptor_cred_handle,
                                 gss_buffer_t input_token_buffer,
                                 gss_channel_bindings_t input_chan_bindings,
                                 gssx_name **src_name,
                                 gss_OID *mech_type,
                                 gss_buffer_t output_token,
                                 OM_uint32 *ret_flags,
                                 OM_uint32 *time_rec,
                                 gssx_cred **delegated_cred_handle);

OM_uint32 gpm_release_cred(OM_uint32 *minor_status,
                           gssx_cred **cred_handle);

OM_uint32 gpm_delete_sec_context(OM_uint32 *minor_status,
                                 gssx_ctx **context_handle,
                                 gss_buffer_t output_token);

OM_uint32 gpm_acquire_cred(OM_uint32 *minor_status,
                           gssx_cred *imp_cred_handle,
                           gssx_name *desired_name,
                           OM_uint32 time_req,
                           const gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           bool impersonate,
                           gssx_cred **output_cred_handle,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec);

OM_uint32 gpm_add_cred(OM_uint32 *minor_status,
                       gssx_cred *input_cred_handle,
                       gssx_name *desired_name,
                       const gss_OID desired_mech,
                       gss_cred_usage_t cred_usage,
                       OM_uint32 initiator_time_req,
                       OM_uint32 acceptor_time_req,
                       gssx_cred **output_cred_handle,
                       gss_OID_set *actual_mechs,
                       OM_uint32 *initiator_time_rec,
                       OM_uint32 *acceptor_time_rec);
OM_uint32 gpm_inquire_cred(OM_uint32 *minor_status,
                           gssx_cred *cred,
                           gssx_name **name,
                           OM_uint32 *lifetime,
                           gss_cred_usage_t *cred_usage,
                           gss_OID_set *mechanisms);
OM_uint32 gpm_inquire_cred_by_mech(OM_uint32 *minor_status,
                                   gssx_cred *cred,
                                   gss_OID mech_type,
                                   gssx_name **name,
                                   OM_uint32 *initiator_lifetime,
                                   OM_uint32 *acceptor_lifetime,
                                   gss_cred_usage_t *cred_usage);

OM_uint32 gpm_indicate_mechs(OM_uint32 *minor_status, gss_OID_set *mech_set);
OM_uint32 gpm_inquire_names_for_mech(OM_uint32 *minor_status,
                                     gss_OID mech_type,
                                     gss_OID_set *mech_names);
OM_uint32 gpm_inquire_mechs_for_name(OM_uint32 *minor_status,
                                     gssx_name *input_name,
                                     gss_OID_set *mech_types);
OM_uint32 gpm_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                     gss_OID mech,
                                     gss_OID_set *mech_attrs,
                                     gss_OID_set *known_mech_attrs);
OM_uint32 gpm_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                        const gss_OID desired_mech,
                                        gss_buffer_t sasl_mech_name,
                                        gss_buffer_t mech_name,
                                        gss_buffer_t mech_description);
OM_uint32 gpm_display_mech_attr(OM_uint32 *minor_status,
                                gss_const_OID mech_attr,
                                gss_buffer_t name,
                                gss_buffer_t short_desc,
                                gss_buffer_t long_desc);
OM_uint32 gpm_indicate_mechs_by_attrs(OM_uint32 *minor_status,
                                      gss_const_OID_set desired_mech_attrs,
                                      gss_const_OID_set except_mech_attrs,
                                      gss_const_OID_set critical_mech_attrs,
                                      gss_OID_set *mechs);

OM_uint32 gpm_display_name(OM_uint32 *minor_status,
                           gssx_name *in_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type);
OM_uint32 gpm_import_name(OM_uint32 *minor_status,
                          gss_buffer_t input_name_buffer,
                          gss_OID input_name_type,
                          gssx_name **output_name);
OM_uint32 gpm_export_name(OM_uint32 *minor_status,
                          gssx_name *input_name,
                          gss_buffer_t exported_name);
OM_uint32 gpm_export_name_composite(OM_uint32 *minor_status,
                                    gssx_name *input_name,
                                    gss_buffer_t exported_composite_name);
OM_uint32 gpm_duplicate_name(OM_uint32 *minor_status,
                             gssx_name *input_name,
                             gssx_name **dest_name);
OM_uint32 gpm_canonicalize_name(OM_uint32 *minor_status,
                                gssx_name *input_name,
                                const gss_OID mech_type,
                                gssx_name **output_name);
OM_uint32 gpm_inquire_name(OM_uint32 *minor_status,
                           gssx_name *name,
                           int *name_is_NM,
                           gss_OID *NM_mech,
                           gss_buffer_set_t *attrs);
OM_uint32 gpm_compare_name(OM_uint32 *minor_status,
                           gssx_name *name1,
                           gssx_name *name2,
                           int *name_equal);

OM_uint32 gpm_init_sec_context(OM_uint32 *minor_status,
                               gssx_cred *cred_handle,
                               gssx_ctx **context_handle,
                               gssx_name *target_name,
                               gss_OID mech_type,
                               OM_uint32 req_flags,
                               OM_uint32 time_req,
                               gss_channel_bindings_t input_cb,
                               gss_buffer_t input_token,
                               gss_OID *actual_mech_type,
                               gss_buffer_t output_token,
                               OM_uint32 *ret_flags,
                               OM_uint32 *time_rec,
                               gssx_cred **out_cred_handle);
OM_uint32 gpm_inquire_context(OM_uint32 *minor_status,
                              gssx_ctx *context_handle,
                              gssx_name **src_name,
                              gssx_name **targ_name,
                              OM_uint32 *lifetime_rec,
                              gss_OID *mech_type,
                              OM_uint32 *ctx_flags,
                              int *locally_initiated,
                              int *open);

OM_uint32 gpm_get_mic(OM_uint32 *minor_status,
                      gssx_ctx *context_handle,
                      gss_qop_t qop_req,
                      gss_buffer_t message_buffer,
                      gss_buffer_t message_token);
OM_uint32 gpm_verify_mic(OM_uint32 *minor_status,
                         gssx_ctx *context_handle,
                         gss_buffer_t message_buffer,
                         gss_buffer_t message_token,
                         gss_qop_t *qop_state);
OM_uint32 gpm_wrap(OM_uint32 *minor_status,
                   gssx_ctx *context_handle,
                   int conf_req_flag,
                   gss_qop_t qop_req,
                   const gss_buffer_t input_message_buffer,
                   int *conf_state,
                   gss_buffer_t output_message_buffer);
OM_uint32 gpm_unwrap(OM_uint32 *minor_status,
                     gssx_ctx *context_handle,
                     const gss_buffer_t input_message_buffer,
                     gss_buffer_t output_message_buffer,
                     int *conf_state,
                     gss_qop_t *qop_state);
OM_uint32 gpm_wrap_size_limit(OM_uint32 *minor_status,
                              gssx_ctx *context_handle,
                              int conf_req,
                              gss_qop_t qop_req,
                              OM_uint32 size_req,
                              OM_uint32 *max_size);
#endif /* _GSSAPI_GPM_H_ */
