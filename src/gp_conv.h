/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GSS_CONV_H_
#define _GSS_CONV_H_

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include "rpcgen/gss_proxy.h"

void *gp_memdup(void *in, size_t len);
int gp_conv_octet_string(size_t length, void *value, octet_string *out);
int gp_conv_octet_string_alloc(size_t length, void *value,
                               octet_string **out);

void gp_conv_gssx_to_oid(gssx_OID *in, gss_OID out);
int gp_conv_gssx_to_oid_alloc(gssx_OID *in, gss_OID *out);
int gp_conv_oid_to_gssx(gss_OID in, gssx_OID *out);
int gp_conv_oid_to_gssx_alloc(gss_OID in, gssx_OID **out);

void gp_conv_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out);
int gp_conv_gssx_to_buffer_alloc(gssx_buffer *in, gss_buffer_t *out);
int gp_copy_gssx_to_buffer(gssx_buffer *in, gss_buffer_t out);
int gp_copy_gssx_to_string_buffer(gssx_buffer *in, gss_buffer_t out);
int gp_conv_buffer_to_gssx(gss_buffer_t in, gssx_buffer *out);
int gp_conv_buffer_to_gssx_alloc(gss_buffer_t in, gssx_buffer **out);

void gp_conv_gssx_to_cb(gssx_cb *in, gss_channel_bindings_t out);
int gp_conv_cb_to_gssx(gss_channel_bindings_t in, gssx_cb *out);
int gp_conv_cb_to_gssx_alloc(gss_channel_bindings_t in, gssx_cb **out);

gssx_cred_usage gp_conv_cred_usage_to_gssx(gss_cred_usage_t in);
gss_cred_usage_t gp_conv_gssx_to_cred_usage(gssx_cred_usage in);

int gp_conv_err_to_gssx_string(uint32_t status, int type, gss_OID oid,
                               utf8string *ret_str);

uint32_t gp_conv_name_to_gssx(uint32_t *min, gss_name_t in, gssx_name *out);
uint32_t gp_conv_name_to_gssx_alloc(uint32_t *min,
                                    gss_name_t in, gssx_name **out);
uint32_t gp_conv_gssx_to_name(uint32_t *min, gssx_name *in, gss_name_t *out);

int gp_conv_status_to_gssx(uint32_t ret_maj, uint32_t ret_min,
                           gss_OID mech, struct gssx_status *status);

int gp_copy_utf8string(utf8string *in, utf8string *out);
int gp_copy_gssx_status_alloc(gssx_status *in, gssx_status **out);

int gp_conv_gssx_to_oid_set(gssx_OID_set *in, gss_OID_set *out);
int gp_conv_oid_set_to_gssx(gss_OID_set in, gssx_OID_set *out);

int gp_copy_gssx_name(gssx_name *in, gssx_name *out);
int gp_copy_gssx_name_alloc(gssx_name *in, gssx_name **out);

#endif /* _GSS_CONV_H_ */
