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

#include "gssapi_gpm.h"

__thread gssx_status *tls_last_status = NULL;

/* Thread local storage for return status.
 * FIXME: it's not the most portable construct, so may need fixing in future */
void gpm_save_status(gssx_status *status)
{
    int ret;

    if (tls_last_status) {
        xdr_free((xdrproc_t)xdr_gssx_status, (char *)tls_last_status);
        free(tls_last_status);
    }

    ret = gp_copy_gssx_status_alloc(status, &tls_last_status);
    if (ret) {
        /* make sure tls_last_status is zeored on error */
        tls_last_status = NULL;
    }
}

OM_uint32 gpm_display_status(OM_uint32 *minor_status,
                             OM_uint32 status_value,
                             int status_type,
                             const gss_OID mech_type,
                             OM_uint32 *message_context,
                             gss_buffer_t status_string)
{
    utf8string tmp;
    int ret;

    switch(status_type) {
    case GSS_C_GSS_CODE:
        if (tls_last_status &&
            tls_last_status->major_status_string.utf8string_len) {
                ret = gp_copy_utf8string(&tls_last_status->major_status_string,
                                         &tmp);
                if (ret) {
                    *minor_status = ret;
                    return GSS_S_FAILURE;
                }
                status_string->value = tmp.utf8string_val;
                status_string->length = tmp.utf8string_len;
                *minor_status = 0;
                return GSS_S_COMPLETE;
        } else {
            return gss_display_status(minor_status,
                                      status_value,
                                      GSS_C_GSS_CODE,
                                      GSS_C_NO_OID,
                                      message_context,
                                      status_string);
        }
    case GSS_C_MECH_CODE:
        if (*message_context) {
            /* we do not support multiple messages for now */
            *minor_status = EINVAL;
            return GSS_S_FAILURE;
        }
        if (tls_last_status &&
            tls_last_status->minor_status_string.utf8string_len) {
            ret = gp_copy_utf8string(&tls_last_status->minor_status_string,
                                     &tmp);
            if (ret) {
                *minor_status = ret;
                return GSS_S_FAILURE;
            }
            status_string->value = tmp.utf8string_val;
            status_string->length = tmp.utf8string_len;
        } else {
            status_string->value = strdup(strerror(status_value));
            if (!status_string->value) {
                status_string->length = 0;
                *minor_status = ENOMEM;
                return GSS_S_FAILURE;
            } else {
                status_string->length = strlen(status_string->value) + 1;
            }
        }
        *minor_status = 0;
        return GSS_S_COMPLETE;
    default:
        *minor_status = EINVAL;
        return GSS_S_BAD_STATUS;
    }
}
