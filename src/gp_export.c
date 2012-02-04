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

#include "config.h"
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include "gp_conv.h"
#include "gp_export.h"
#include "gp_debug.h"

/* FIXME: F I X M E
 *
 * FFFFF  I  X    X  M    M  EEEEE
 * F      I   X  X   MM  MM  E
 * FFF    I    XX    M MM M  EEE
 * F      I   X  X   M    M  E
 * F      I  X    X  M    M  EEEEE
 *
 * Credential functions should either be implemented with gss_export_cred()
 * or, lacking those calls in the gssapi implementation, by keeping state
 * in a table/list and returning a token.
 * In both cases the content should be encrypted.
 *
 * Temporarily we simply return straight out the gss_cred_id_t pointer as
 * a handle.
 *
 * THIS IS ONLY FOR THE PROTOTYPE
 *
 * *MUST* BE FIXED BEFORE ANY OFFICIAL RELEASE.
 */

int gp_export_gssx_cred(gss_cred_id_t *in, gssx_cred *out)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_name_t name = NULL;
    uint32_t lifetime;
    gss_cred_usage_t cred_usage;
    gss_OID_set mechanisms = NULL;
    uint32_t initiator_lifetime;
    uint32_t acceptor_lifetime;
    struct gssx_cred_element *el;
    int ret;
    int i, j;

    ret_maj = gss_inquire_cred(&ret_min, *in,
                               &name, &lifetime, &cred_usage, &mechanisms);
    if (ret_maj) {
        ret = EINVAL;
        goto done;
    }

    ret = gp_conv_name_to_gssx(name, &out->desired_name);
    if (ret) {
        goto done;
    }
    gss_release_name(&ret_min, &name);
    name = NULL;

    out->elements.elements_len = mechanisms->count;
    out->elements.elements_val = calloc(out->elements.elements_len,
                                        sizeof(gssx_cred_element));
    if (!out->elements.elements_val) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0, j = 0; i < mechanisms->count; i++, j++) {

        el = &out->elements.elements_val[j];

        ret_maj = gss_inquire_cred_by_mech(&ret_min, *in,
                                           &mechanisms->elements[i],
                                           &name,
                                           &initiator_lifetime,
                                           &acceptor_lifetime,
                                           &cred_usage);
        if (ret_maj) {
            gp_log_failure(&mechanisms->elements[i], ret_maj, ret_min);

            /* temporarily skip any offender */
            out->elements.elements_len--;
            j--;
            continue;
#if 0
            ret = EINVAL;
            goto done;
#endif
        }

        ret = gp_conv_name_to_gssx(name, &el->MN);
        if (ret) {
            goto done;
        }
        gss_release_name(&ret_min, &name);
        name = NULL;

        ret = gp_conv_oid_to_gssx(&mechanisms->elements[i], &el->mech);
        if (ret) {
            goto done;
        }
        el->cred_usage = gp_conv_gssx_to_cred_usage(cred_usage);

        el->initiator_time_rec = initiator_lifetime;
        el->acceptor_time_rec = acceptor_lifetime;
    }

    ret = gp_conv_octet_string(sizeof(gss_cred_id_t), in,
                               &out->cred_handle_reference);
    if (ret) {
        goto done;
    }
    out->needs_release = true;

    /* we take over control of the credentials from here on */
    /* when we will have gss_export_cred() we will actually free
     * them immediately instead */
    *in = NULL;

done:
    gss_release_name(&ret_min, &name);
    gss_release_oid_set(&ret_min, &mechanisms);
    return ret;
}

int gp_import_gssx_cred(octet_string *in, gss_cred_id_t *out)
{
    if (in) {
        memcpy(out, in->octet_string_val, sizeof(gss_cred_id_t));
    } else {
        *out = NULL;
    }
    return 0;
}

int gp_find_cred(gssx_cred *cred, gss_cred_id_t *out)
{
    return gp_import_gssx_cred(&cred->cred_handle_reference, out);
}
