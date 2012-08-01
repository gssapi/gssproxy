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
#include <gssapi/gssapi_krb5.h>

#define KRB5_OID_LEN 9
#define KRB5_OID "\052\206\110\206\367\022\001\002\002"

#define KRB5_OLD_OID_LEN 5
#define KRB5_OLD_OID "\053\005\001\005\002"

/* Incorrect krb5 mech OID emitted by MS. */
#define KRB5_WRONG_OID_LEN 9
#define KRB5_WRONG_OID "\052\206\110\202\367\022\001\002\002"

#define IAKERB_OID_LEN 6
#define IAKERB_OID "\053\006\001\005\002\005"

const gss_OID_desc gpoid_krb5 = {
    .length = KRB5_OID_LEN,
    .elements = KRB5_OID
};
const gss_OID_desc gpoid_krb5_old = {
    .length = KRB5_OLD_OID_LEN,
    .elements = KRB5_OLD_OID
};
const gss_OID_desc gpoid_krb5_wrong = {
    .length = KRB5_WRONG_OID_LEN,
    .elements = KRB5_WRONG_OID
};
const gss_OID_desc gpoid_iakerb = {
    .length = IAKERB_OID_LEN,
    .elements = IAKERB_OID
};

enum gpp_behavior gpp_get_behavior(void)
{
    static enum gpp_behavior behavior = GPP_UNINITIALIZED;
    char *envval;

    if (behavior == GPP_UNINITIALIZED) {
        envval = getenv("GSSPROXY_BEHAVIOR");
        if (envval) {
            if (strcmp(envval, "LOCAL_ONLY") == 0) {
                behavior = GPP_LOCAL_ONLY;
            } else if (strcmp(envval, "LOCAL_FIRST") == 0) {
                behavior = GPP_LOCAL_FIRST;
            } else if (strcmp(envval, "REMOTE_FIRST") == 0) {
                behavior = GPP_REMOTE_FIRST;
            } else if (strcmp(envval, "REMOTE_ONLY") == 0) {
                behavior = GPP_REMOTE_ONLY;
            } else {
                /* unknwon setting, default to local first */
                behavior = GPP_LOCAL_FIRST;
            }
        } else {
            /* default to local only for now */
            behavior = GPP_LOCAL_FIRST;
        }
    }

    return behavior;
}

/* 2.16.840.1.113730.3.8.15.1 */
const gss_OID_desc gssproxy_mech_interposer = {
    .length = 11,
    .elements = "\140\206\110\001\206\370\102\003\010\017\001"
};

gss_OID_set gss_mech_interposer(gss_OID mech_type)
{
    gss_OID_set interposed_mechs;
    OM_uint32 maj, min;
    char *envval;

    /* avoid looping in the gssproxy daemon by avoiding to interpose
     * any mechanism */
    envval = getenv("_GSSPROXY_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return NULL;
    }

    interposed_mechs = NULL;
    maj = 0;
    if (gss_oid_equal(&gssproxy_mech_interposer, mech_type)) {
        maj = gss_create_empty_oid_set(&min, &interposed_mechs);
        if (maj != 0) {
            return NULL;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_old),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_wrong),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_iakerb),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
    }

done:
    if (maj != 0) {
        (void)gss_release_oid_set(&min, &interposed_mechs);
        interposed_mechs = NULL;
    }

    return interposed_mechs;
}
