/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Simo Sorce <simo.sorce@redhat.com>

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

#include "gss_plugin.h"

OM_uint32 gssi_accept_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_cred_id_t acceptor_cred_handle,
                                  gss_buffer_t input_token_buffer,
                                  gss_channel_bindings_t input_chan_bindings,
                                  gss_name_t *src_name,
                                  gss_OID *mech_type,
                                  gss_buffer_t output_token,
                                  OM_uint32 *ret_flags,
                                  OM_uint32 *time_rec,
                                  gss_cred_id_t *delegated_cred_handle)
{
    enum gpp_behavior behavior;
    struct gpp_context_handle *ctx_handle = NULL;
    struct gpp_cred_handle *cred_handle = NULL;
    struct gpp_cred_handle *deleg_cred = NULL;
    struct gpp_name_handle *name = NULL;
    OM_uint32 maj, min;

    GSSI_TRACE();

    behavior = gpp_get_behavior();

    if (*context_handle) {
        ctx_handle = (struct gpp_context_handle *)*context_handle;
        if (ctx_handle->local) {
            /* if we already have a local context it means this is
             * a continuation, force local only behavior, nothing else
             * makes sense */
            behavior = GPP_LOCAL_ONLY;
        } else if (ctx_handle->remote) {
            behavior = GPP_REMOTE_ONLY;
        }
    } else {
        ctx_handle = calloc(1, sizeof(struct gpp_context_handle));
        if (!ctx_handle) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
    }

    if (acceptor_cred_handle != GSS_C_NO_CREDENTIAL) {
        cred_handle = (struct gpp_cred_handle *)acceptor_cred_handle;
    } else {
        maj = gppint_get_def_creds(&min, behavior, NULL,
                                   GSS_C_ACCEPT, &cred_handle);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }
    if (cred_handle->local) {
        if (behavior == GPP_REMOTE_ONLY) {
            min = 0;
            maj = GSS_S_DEFECTIVE_CREDENTIAL;
            goto done;
        }
        behavior = GPP_LOCAL_ONLY;
    } else if (cred_handle->remote) {
        if (behavior == GPP_LOCAL_ONLY) {
            min = 0;
            maj = GSS_S_DEFECTIVE_CREDENTIAL;
            goto done;
        }
        behavior = GPP_REMOTE_ONLY;
    }

    if (src_name) {
        name = calloc(1, sizeof(struct gpp_name_handle));
        if (!name) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
    }

    if (delegated_cred_handle) {
        deleg_cred = calloc(1, sizeof(struct gpp_cred_handle));
        if (!deleg_cred) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
    }

    /* behavior has been set to local only or remote only by context or
     * credential handler inspection, so we only have those 2 cases,
     * anything else is an error at this point. */
    if (behavior == GPP_LOCAL_ONLY) {

        maj = gss_accept_sec_context(&min, &ctx_handle->local,
                                     cred_handle->local, input_token_buffer,
                                     input_chan_bindings,
                                     name ? &name->local : NULL, mech_type,
                                     output_token, ret_flags, time_rec,
                                     deleg_cred ? &deleg_cred->local : NULL);
    } else if (behavior == GPP_REMOTE_ONLY) {

        maj = gpm_accept_sec_context(&min, &ctx_handle->remote,
                                     cred_handle->remote, input_token_buffer,
                                     input_chan_bindings,
                                     name ? &name->remote : NULL, mech_type,
                                     output_token, ret_flags, time_rec,
                                     deleg_cred ? &deleg_cred->remote : NULL);
    } else {

        min = 0;
        maj = GSS_S_FAILURE;
    }

done:
    *minor_status = gpp_map_error(min);
    if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
        if (ctx_handle &&
            ctx_handle->local == GSS_C_NO_CONTEXT &&
            ctx_handle->remote == NULL) {
            free(ctx_handle);
            ctx_handle = NULL;
        }
        free(deleg_cred);
        free(name);
    } else {
        if (src_name) {
            *src_name = (gss_name_t)name;
        }
        if (delegated_cred_handle) {
            *delegated_cred_handle = (gss_cred_id_t)deleg_cred;
        }
    }
    /* always replace the provided context handle to avoid
     * dangling pointers when a context has been passed in */
    *context_handle = (gss_ctx_id_t)ctx_handle;

    if (acceptor_cred_handle == GSS_C_NO_CREDENTIAL) {
        (void)gssi_release_cred(&min, (gss_cred_id_t *)&cred_handle);
    }
    return maj;
}
