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

#ifndef _GSSAPI_GPM_H_
#define _GSSAPI_GPM_H_

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "rpcgen/gp_rpc.h"
#include "rpcgen/gss_proxy.h"
#include "src/gp_common.h"
#include "src/gp_conv.h"

int gpm_make_call(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res);
void gpm_free_xdrs(int proc, union gp_rpc_arg *arg, union gp_rpc_res *res);

OM_uint32 gpm_release_name(OM_uint32 *minor_status,
                           gss_name_t *input_name);
OM_uint32 gpm_release_buffer(OM_uint32 *minor_status,
                             gss_buffer_t buffer);

void gpm_save_status(gssx_status *status);
void gpm_save_internal_status(uint32_t err, char *err_str);

OM_uint32 gpm_display_status(OM_uint32 *minor_status,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string);

OM_uint32 gpm_accept_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_cred_id_t acceptor_cred_handle,
                                 gss_buffer_t input_token_buffer,
                                 gss_channel_bindings_t input_chan_bindings,
                                 gss_name_t *src_name,
                                 gss_OID *mech_type,
                                 gss_buffer_t output_token,
                                 OM_uint32 *ret_flags,
                                 OM_uint32 *time_rec,
                                 gss_cred_id_t *delegated_cred_handle);

OM_uint32 gpm_release_cred(OM_uint32 *minor_status,
                           gss_cred_id_t *cred_handle);

OM_uint32 gpm_delete_sec_context(OM_uint32 *minor_status,
                                 gss_ctx_id_t *context_handle,
                                 gss_buffer_t output_token);

OM_uint32 gpm_acquire_cred(OM_uint32 *minor_status,
                           const gss_name_t desired_name,
                           OM_uint32 time_req,
                           const gss_OID_set desired_mechs,
                           gss_cred_usage_t cred_usage,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           OM_uint32 *time_rec);

OM_uint32 gpm_add_cred(OM_uint32 *minor_status,
                       const gss_cred_id_t input_cred_handle,
                       const gss_name_t desired_name,
                       const gss_OID desired_mech,
                       gss_cred_usage_t cred_usage,
                       OM_uint32 initiator_time_req,
                       OM_uint32 acceptor_time_req,
                       gss_cred_id_t *output_cred_handle,
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
                                     const gss_name_t input_name,
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
                           gss_name_t input_name,
                           gss_buffer_t output_name_buffer,
                           gss_OID *output_name_type);
OM_uint32 gpm_import_name(OM_uint32 *minor_status,
                          gss_buffer_t input_name_buffer,
                          gss_OID input_name_type,
                          gss_name_t *output_name);
OM_uint32 gpm_export_name(OM_uint32 *minor_status,
                          const gss_name_t input_name,
                          gss_buffer_t exported_name);
OM_uint32 gpm_duplicate_name(OM_uint32 *minor_status,
                             const gss_name_t input_name,
                             gss_name_t *dest_name);
OM_uint32 gpm_canonicalize_name(OM_uint32 *minor_status,
                                const gss_name_t input_name,
                                const gss_OID mech_type,
                                gss_name_t *output_name);
OM_uint32 gpm_inquire_name(OM_uint32 *minor_status,
                           gss_name_t name,
                           int *name_is_NM,
                           gss_OID *NM_mech,
                           gss_buffer_set_t *attrs);

OM_uint32 gpm_init_sec_context(OM_uint32 *minor_status,
                               gss_cred_id_t claimant_cred_handle,
                               gss_ctx_id_t *context_handle,
                               gss_name_t target_name,
                               gss_OID mech_type,
                               OM_uint32 req_flags,
                               OM_uint32 time_req,
                               gss_channel_bindings_t input_cb,
                               gss_buffer_t input_token,
                               gss_OID *actual_mech_type,
                               gss_buffer_t output_token,
                               OM_uint32 *ret_flags,
                               OM_uint32 *time_rec);
#endif /* _GSSAPI_GPM_H_ */
