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
