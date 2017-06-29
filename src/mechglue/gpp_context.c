/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"
#include <time.h>

OM_uint32 gssi_export_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t interprocess_token)
{
    struct gpp_context_handle *ctx;
    gss_buffer_desc output_token;
    OM_uint32 maj, min;

    GSSI_TRACE();

    ctx = (struct gpp_context_handle *)context_handle;
    if (!ctx) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote && !ctx->local) {
        maj = gpp_remote_to_local_ctx(&min, &ctx->remote, &ctx->local);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
    }

    maj = gss_export_sec_context(minor_status, &ctx->local,
                                 interprocess_token);

    if (maj == GSS_S_COMPLETE && ctx->remote) {
        (void)gpm_delete_sec_context(&min, &ctx->remote, &output_token);
    }

    return maj;
}

OM_uint32 gssi_import_sec_context(OM_uint32 *minor_status,
                                  gss_buffer_t interprocess_token,
                                  gss_ctx_id_t *context_handle)
{
    GSSI_TRACE();
    return GSS_S_UNAVAILABLE;
}

OM_uint32 gssi_import_sec_context_by_mech(OM_uint32 *minor_status,
                                          gss_OID mech_type,
                                          gss_buffer_t interprocess_token,
                                          gss_ctx_id_t *context_handle)
{
    struct gpp_context_handle *ctx;
    gss_buffer_desc wrap_token = {0};
    OM_uint32 maj, min = 0;

    GSSI_TRACE();

    ctx = calloc(1, sizeof(struct gpp_context_handle));
    if (!ctx) {
        *minor_status = 0;
        return GSS_S_FAILURE;
    }

    /* NOTE: it makes no sense to import a context remotely atm,
     * so we only handle the local case for now. */
    maj = gpp_wrap_sec_ctx_token(&min, mech_type,
                                 interprocess_token, &wrap_token);
    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    maj = gss_import_sec_context(&min, &wrap_token, &ctx->local);

done:
    *minor_status = gpp_map_error(min);
    if (maj == GSS_S_COMPLETE) {
        *context_handle = (gss_ctx_id_t)ctx;
    } else {
        free(ctx);
    }
    (void)gss_release_buffer(&min, &wrap_token);
    return maj;
}

OM_uint32 gssi_process_context_token(OM_uint32 *minor_status,
                                     gss_ctx_id_t context_handle,
                                     gss_buffer_t token_buffer)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;

    GSSI_TRACE();

    ctx = (struct gpp_context_handle *)context_handle;
    if (!ctx) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote && !ctx->local) {
        maj = gpp_remote_to_local_ctx(&min, &ctx->remote, &ctx->local);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
    }

    return gss_process_context_token(minor_status, ctx->local, token_buffer);
}

OM_uint32 gssi_context_time(OM_uint32 *minor_status,
                            gss_ctx_id_t context_handle,
                            OM_uint32 *time_rec)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;

    GSSI_TRACE();

    *minor_status = 0;

    ctx = (struct gpp_context_handle *)context_handle;
    if (!ctx) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote) {
        OM_uint32 lifetime;
        maj = gpm_inquire_context(&min, ctx->remote, NULL, NULL,
                                  &lifetime, NULL, NULL, NULL, NULL);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
        if (lifetime > 0) {
            *time_rec = lifetime;
            return GSS_S_COMPLETE;
        } else {
            *time_rec = 0;
            return GSS_S_CONTEXT_EXPIRED;
        }
    } else if (ctx->local) {
        return gss_context_time(minor_status, ctx->local, time_rec);
    } else {
        return GSS_S_NO_CONTEXT;
    }
}

OM_uint32 gssi_inquire_context(OM_uint32 *minor_status,
                              gss_ctx_id_t context_handle,
                              gss_name_t *src_name,
                              gss_name_t *targ_name,
                              OM_uint32 *lifetime_rec,
                              gss_OID *mech_type,
                              OM_uint32 *ctx_flags,
                              int *locally_initiated,
                              int *open)
{
    struct gpp_context_handle *ctx_handle;
    struct gpp_name_handle *s_name = NULL;
    struct gpp_name_handle *t_name = NULL;
    gss_OID mech_oid;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (!context_handle) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    ctx_handle = (struct gpp_context_handle *)context_handle;
    if (!ctx_handle->local &&
        !ctx_handle->remote) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    if (src_name) {
        s_name = calloc(1, sizeof(struct gpp_name_handle));
        if (!s_name) {
            min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
    }
    if (targ_name) {
        t_name = calloc(1, sizeof(struct gpp_name_handle));
        if (!t_name) {
            min = ENOMEM;
            maj = GSS_S_FAILURE;
            goto done;
        }
    }

    if (ctx_handle->local) {
        maj = gss_inquire_context(&min,
                                  ctx_handle->local,
                                  s_name ? &s_name->local : NULL,
                                  t_name ? &t_name->local : NULL,
                                  lifetime_rec,
                                  &mech_oid,
                                  ctx_flags,
                                  locally_initiated,
                                  open);
    } else {
        maj = gpm_inquire_context(&min,
                                  ctx_handle->remote,
                                  s_name ? &s_name->remote : NULL,
                                  t_name ? &t_name->remote : NULL,
                                  lifetime_rec,
                                  &mech_oid,
                                  ctx_flags,
                                  locally_initiated,
                                  open);
    }

    if (maj != GSS_S_COMPLETE) {
        goto done;
    }

    if (s_name) {
        maj = gpp_copy_oid(&min, mech_oid, &s_name->mech_type);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

    if (t_name) {
        maj = gpp_copy_oid(&min, mech_oid, &t_name->mech_type);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
    }

done:
    *minor_status = gpp_map_error(min);
    if (maj == GSS_S_COMPLETE) {
        if (mech_type) {
            *mech_type = mech_oid;
        } else {
            (void)gss_release_oid(&min, &mech_oid);
        }
        if (src_name) {
            *src_name = (gss_name_t)s_name;
        }
        if (targ_name) {
            *targ_name = (gss_name_t)t_name;
        }
    } else {
        (void)gss_release_oid(&min, &mech_oid);
        (void)gssi_release_name(&min, (gss_name_t *)&s_name);
        (void)gssi_release_name(&min, (gss_name_t *)&t_name);
    }
    return maj;
}

OM_uint32 gssi_inquire_sec_context_by_oid(OM_uint32 *minor_status,
                                          const gss_ctx_id_t context_handle,
                                          const gss_OID desired_object,
                                          gss_buffer_set_t *data_set)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;

    GSSI_TRACE();

    ctx = (struct gpp_context_handle *)context_handle;
    if (!ctx) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote && !ctx->local) {
        maj = gpp_remote_to_local_ctx(&min, &ctx->remote, &ctx->local);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
    }

    return gss_inquire_sec_context_by_oid(minor_status, ctx->local,
                                          desired_object, data_set);
}

OM_uint32 gssi_set_sec_context_option(OM_uint32 *minor_status,
                                      gss_ctx_id_t *context_handle,
                                      const gss_OID desired_object,
                                      const gss_buffer_t value)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;

    GSSI_TRACE();

    if (*context_handle) {
        ctx = (struct gpp_context_handle *)(*context_handle);
    } else {
        ctx = calloc(1, sizeof(struct gpp_context_handle));
        if (!ctx) {
            *minor_status = 0;
            return GSS_S_FAILURE;
        }
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote && !ctx->local) {
        maj = gpp_remote_to_local_ctx(&min, &ctx->remote, &ctx->local);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            goto done;
        }
    }

    maj = gss_set_sec_context_option(minor_status, &ctx->local,
                                     desired_object, value);
done:
    *context_handle = (gss_ctx_id_t)ctx;
    if (maj != GSS_S_COMPLETE) {
        (void)gssi_delete_sec_context(&min, context_handle, NULL);
    }
    return maj;
}

OM_uint32 gssi_delete_sec_context(OM_uint32 *minor_status,
                                  gss_ctx_id_t *context_handle,
                                  gss_buffer_t output_token)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;
    OM_uint32 rmaj = GSS_S_COMPLETE;

    GSSI_TRACE();

    ctx = (struct gpp_context_handle *)*context_handle;

    *context_handle = GSS_C_NO_CONTEXT;

    if (ctx == NULL) {
        *minor_status = 0;
        return GSS_S_COMPLETE;
    }

    if (ctx->local) {
        maj = gss_delete_sec_context(&min, &ctx->local, output_token);
        if (maj != GSS_S_COMPLETE) {
            rmaj = maj;
            *minor_status = gpp_map_error(min);
        }
    }

    if (ctx->remote) {
        maj = gpm_delete_sec_context(&min, &ctx->remote, output_token);
        if (maj && rmaj == GSS_S_COMPLETE) {
            rmaj = maj;
            *minor_status = gpp_map_error(min);
        }
    }

    free(ctx);

    return rmaj;
}

OM_uint32 gssi_pseudo_random(OM_uint32 *minor_status,
                             gss_ctx_id_t context_handle,
                             int prf_key,
                             const gss_buffer_t prf_in,
                             ssize_t desired_output_len,
                             gss_buffer_t prf_out)
{
    struct gpp_context_handle *ctx;
    OM_uint32 maj, min;

    GSSI_TRACE();

    ctx = (struct gpp_context_handle *)context_handle;
    if (!ctx) {
        return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* for now we have support only for some specific known
     * mechanisms for which we can export/import the context */
    if (ctx->remote && !ctx->local) {
        maj = gpp_remote_to_local_ctx(&min, &ctx->remote, &ctx->local);
        if (maj != GSS_S_COMPLETE) {
            *minor_status = gpp_map_error(min);
            return maj;
        }
    }

    return gss_pseudo_random(minor_status,
                             ctx->local, prf_key, prf_in,
                             desired_output_len, prf_out);
}
