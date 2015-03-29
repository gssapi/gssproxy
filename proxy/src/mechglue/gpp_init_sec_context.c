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

static OM_uint32 init_ctx_local(OM_uint32 *minor_status,
                                struct gpp_cred_handle *cred_handle,
                                struct gpp_context_handle *ctx_handle,
                                struct gpp_name_handle *name,
                                gss_OID mech_type,
                                OM_uint32 req_flags,
                                OM_uint32 time_req,
                                gss_channel_bindings_t input_cb,
                                gss_buffer_t input_token,
                                gss_OID *actual_mech_type,
                                gss_buffer_t output_token,
                                OM_uint32 *ret_flags,
                                OM_uint32 *time_rec)
{
    OM_uint32 maj, min;

    if (name->remote && !name->local) {
        maj = gpp_name_to_local(&min, name->remote,
                                mech_type, &name->local);
        if (maj) {
            goto done;
        }
    }

    maj = gss_init_sec_context(&min,
                               cred_handle->local,
                               &ctx_handle->local,
                               name->local,
                               gpp_special_mech(mech_type),
                               req_flags,
                               time_req,
                               input_cb,
                               input_token,
                               actual_mech_type,
                               output_token,
                               ret_flags,
                               time_rec);

done:
    *minor_status = min;
    return maj;
}

OM_uint32 gssi_init_sec_context(OM_uint32 *minor_status,
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
                                OM_uint32 *time_rec)
{
    enum gpp_behavior behavior = GPP_UNINITIALIZED;
    struct gpp_context_handle *ctx_handle = NULL;
    struct gpp_cred_handle *cred_handle = NULL;
    struct gpp_name_handle *name;
    OM_uint32 tmaj, tmin;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;

    if (target_name == GSS_C_NO_NAME) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (mech_type == GSS_C_NO_OID || gpp_is_special_oid(mech_type)) {
        return GSS_S_BAD_MECH;
    }

    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    if (*context_handle) {
        ctx_handle = (struct gpp_context_handle *)*context_handle;
        if (ctx_handle->local) {
            /* ok this means a previous call decided to use the local mech,
             * so let's just re-enter the mechglue here and keep at it */
            behavior = GPP_LOCAL_ONLY;
        }
    } else {
        ctx_handle = calloc(1, sizeof(struct gpp_context_handle));
        if (!ctx_handle) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
    }

    if (claimant_cred_handle != GSS_C_NO_CREDENTIAL) {
        cred_handle = (struct gpp_cred_handle *)claimant_cred_handle;
        if (cred_handle->local) {
            /* ok this means a previous call decided to short circuit to the
             * local mech, so let's just re-enter the mechglue here, as we
             * have no way to export creds yet. */
            behavior = GPP_LOCAL_ONLY;
        } else if (behavior == GPP_LOCAL_ONLY) {
            maj = GSS_S_DEFECTIVE_CREDENTIAL;
            min = 0;
            goto done;
        }
    } else {
        cred_handle =  calloc(1, sizeof(struct gpp_cred_handle));
        if (!cred_handle) {
            maj = GSS_S_FAILURE;
            min = ENOMEM;
            goto done;
        }
    }

    name = (struct gpp_name_handle *)target_name;
    if (behavior == GPP_UNINITIALIZED) {
        behavior = gpp_get_behavior();
    }

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = init_ctx_local(&min, cred_handle, ctx_handle, name,
                              mech_type, req_flags, time_req, input_cb,
                              input_token, actual_mech_type, output_token,
                              ret_flags, time_rec);

        if (maj == GSS_S_COMPLETE || maj == GSS_S_CONTINUE_NEEDED ||
            behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (behavior != GPP_LOCAL_ONLY) {

        if (name->local && !name->remote) {
            maj = gpp_local_to_name(&min, name->local, &name->remote);
            if (maj) {
                goto done;
            }
        }

        maj = gpm_init_sec_context(&min,
                                   cred_handle->remote,
                                   &ctx_handle->remote,
                                   name->remote,
                                   mech_type,
                                   req_flags,
                                   time_req,
                                   input_cb,
                                   input_token,
                                   actual_mech_type,
                                   output_token,
                                   ret_flags,
                                   time_rec);
        if (maj == GSS_S_COMPLETE || maj == GSS_S_CONTINUE_NEEDED ||
            behavior == GPP_REMOTE_ONLY) {
            goto done;
        }

        /* So remote failed, but we can fallback to local, try that */
        maj = init_ctx_local(&min, cred_handle, ctx_handle, name,
                             mech_type, req_flags, time_req, input_cb,
                             input_token, actual_mech_type, output_token,
                             ret_flags, time_rec);
    }

done:
    if (maj != GSS_S_COMPLETE &&
        maj != GSS_S_CONTINUE_NEEDED &&
        tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
        if (ctx_handle &&
            ctx_handle->local == GSS_C_NO_CONTEXT &&
            ctx_handle->remote == NULL) {
            free(ctx_handle);
            ctx_handle = NULL;
        }
        *minor_status = gpp_map_error(min);
    }
    /* always replace the provided context handle to avoid
     * dangling pointers when a context has been passed in */
    *context_handle = (gss_ctx_id_t)ctx_handle;

    if (claimant_cred_handle == GSS_C_NO_CREDENTIAL) {
        free(cred_handle);
    }
    return maj;
}
