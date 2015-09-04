/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"

OM_uint32 gssi_display_status(OM_uint32 *minor_status,
                              OM_uint32 status_value,
                              int status_type,
                              const gss_OID mech_type,
                              OM_uint32 *message_context,
                              gss_buffer_t status_string)
{
    OM_uint32 maj, min, val;

    GSSI_TRACE();

    /* This function is only ever called for minor status values */
    if (status_type != GSS_C_MECH_CODE) {
        return GSS_S_BAD_STATUS;
    }

    val = gpp_unmap_error(status_value);

    maj = gpm_display_status(&min,
                             val,
                             GSS_C_MECH_CODE,
                             GSS_C_NO_OID,
                             message_context,
                             status_string);

    /* if we do not have a matching saved error code
     * try to see if we can come up with one from the
     * mechglue by re-entering it.
     * We do not spcify the mech in this case it's not used by
     * the mechglue anyways */
    if (maj == GSS_S_UNAVAILABLE) {

        return gss_display_status(minor_status,
                                  val,
                                  GSS_C_MECH_CODE,
                                  GSS_C_NO_OID,
                                  message_context,
                                  status_string);
    }

    *minor_status = min;
    return maj;
}
