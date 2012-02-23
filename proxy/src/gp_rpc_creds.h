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

#ifndef _GP_RPC_CREDS_H_
#define _GP_RPC_CREDS_H_

#include "config.h"
#include <stdint.h>
#include <gssapi/gssapi.h>

struct gp_service;

bool gp_creds_allowed_mech(struct gp_service *svc, gss_OID desired_mech);
uint32_t gp_get_supported_mechs(uint32_t *min,
                                struct gp_service *svc, gss_OID_set *set);

uint32_t gp_add_krb5_creds(uint32_t *min,
                           struct gp_service *svc,
                           gss_cred_id_t in_cred,
                           gss_name_t desired_name,
                           gss_cred_usage_t cred_usage,
                           uint32_t initiator_time_req,
                           uint32_t acceptor_time_req,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           uint32_t *initiator_time_rec,
                           uint32_t *acceptor_time_rec);
#endif /* _GP_RPC_CREDS_H_ */
