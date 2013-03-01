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
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>
#include "gp_proxy.h"
#include "gp_rpc_creds.h"
#include "gp_creds.h"

#define GSS_MECH_KRB5_OID_LENGTH 9
#define GSS_MECH_KRB5_OID "\052\206\110\206\367\022\001\002\002"

gss_OID_desc gp_mech_krb5 = { GSS_MECH_KRB5_OID_LENGTH, GSS_MECH_KRB5_OID };

struct supported_mechs_map {
    int internal_id;
    const gss_OID mech;
} supported_mechs_map[] = {
    { GP_CRED_KRB5, &gp_mech_krb5 },
    { 0, NULL }
};

bool gp_creds_allowed_mech(struct gp_service *svc, gss_OID desired_mech)
{
    int i;

    for (i = 0; supported_mechs_map[i].internal_id != 0; i++) {
        if (svc->mechs & supported_mechs_map[i].internal_id) {
            if (gss_oid_equal(desired_mech, supported_mechs_map[i].mech)) {
                return true;
            }
        }
    }

    return false;
}

uint32_t gp_get_supported_mechs(uint32_t *min,
                                struct gp_service *svc, gss_OID_set *set)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    int i;

    ret_maj = gss_create_empty_oid_set(&ret_min, set);
    if (ret_maj) {
        *min = ret_min;
        return ret_maj;
    }

    for (i = 0; supported_mechs_map[i].internal_id != 0; i++) {
        ret_maj = gss_add_oid_set_member(&ret_min,
                                         supported_mechs_map[i].mech, set);
        if (ret_maj) {
            *min = ret_min;
            gss_release_oid_set(&ret_min, set);
            return ret_maj;
        }
    }

    *min = 0;
    return GSS_S_COMPLETE;
}

struct gp_service *gp_creds_match_conn(struct gssproxy_ctx *gpctx,
                                       struct gp_conn *conn)
{
    struct gp_creds *gcs;
    int i;

    gcs = gp_conn_get_creds(conn);

    for (i = 0; i < gpctx->config->num_svcs; i++) {
        if (gpctx->config->svcs[i]->euid == gcs->ucred.uid) {
            return gpctx->config->svcs[i];
        }
    }

    return NULL;
}

static char *gp_get_ccache_name(struct gp_service *svc,
                                gss_name_t desired_name)
{
    char buffer[2048];
    struct passwd pwd, *res = NULL;
    char *ccache;
    char *tmp;
    char *p;
    int ret;

    if (svc->krb5.ccache == NULL) {
        ret = getpwuid_r(svc->euid, &pwd, buffer, 2048, &res);
        if (ret || !res) {
            return NULL;
        }

        ret = asprintf(&ccache, "%s/krb5cc_%s", CCACHE_PATH, pwd.pw_name);
        if (ret == -1) {
            return NULL;
        }

        return ccache;
    }

    ccache = strdup(svc->krb5.ccache);
    if (!ccache) {
        return NULL;
    }

    p = ccache;
    while ((p = strchr(p, '%')) != NULL) {
        p++;
        switch (*p) {
        case '%':
            p++;
            continue;
        case 'u':
            if (!res) {
                ret = getpwuid_r(svc->euid, &pwd, buffer, 2048, &res);
                if (ret || !res) {
                    free(ccache);
                    return NULL;
                }
            }
            ret = asprintf(&tmp, "%.*s%s%s",
                            (int)(p - ccache - 1), ccache, pwd.pw_name,  p + 1);
            if (ret == -1) {
                free(ccache);
                return NULL;
            }
            p = p - ccache + tmp;
            free(ccache);
            ccache = tmp;
            break;
        default:
            p++;
            continue;
        }
    }

    return ccache;
}

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
                           uint32_t *acceptor_time_rec)
{
    char *ccache_name;
    krb5_context kctx;
    krb5_principal principal = NULL;
    krb5_keytab keytab = NULL;
    krb5_ccache ccache = NULL;
    krb5_error_code kerr;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uint32_t discard;

    if (!min || !output_cred_handle) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *min = 0;
    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs) {
        *actual_mechs = GSS_C_NO_OID_SET;
    }

    if (in_cred != GSS_C_NO_CREDENTIAL) {
        /* we can't yet handle adding to an existing credential due to
         * the way gss_krb5_import_cred works. This limitation should
         * be removed by adding a gssapi extension that superceedes this
         * function completely */
        return GSS_S_CRED_UNAVAIL;
    }

    kerr = krb5_init_context(&kctx);
    if (kerr != 0) {
        *min = kerr;
        return GSS_S_FAILURE;
    }

    if (cred_usage == GSS_C_ACCEPT && svc->krb5.keytab == NULL) {
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    if (cred_usage == GSS_C_BOTH || cred_usage == GSS_C_INITIATE) {
        ccache_name = gp_get_ccache_name(svc, desired_name);
        if (!ccache_name) {
            ret_maj = GSS_S_CRED_UNAVAIL;
            goto done;
        }

        kerr = krb5_cc_resolve(kctx, ccache_name, &ccache);
        if (kerr) {
            ret_maj = GSS_S_FAILURE;
            ret_min = kerr;
            goto done;
        }

        /* FIXME: initiate ? */
    }

    if (desired_name) {
        /* FIXME: resolve principal name */
    }

    if (svc->krb5.keytab) {
        kerr = krb5_kt_resolve(kctx, svc->krb5.keytab, &keytab);
        if (kerr != 0) {
            ret_maj = GSS_S_FAILURE;
            ret_min = kerr;
            goto done;
        }
    }

    ret_maj = gss_krb5_import_cred(&ret_min,
                                   ccache, principal, keytab,
                                   output_cred_handle);
    if (ret_maj) {
        goto done;
    }

    if (actual_mechs) {
        ret_maj = gss_create_empty_oid_set(&ret_min, actual_mechs);
        if (ret_maj) {
            goto done;
        }
        ret_maj = gss_add_oid_set_member(&ret_min,
                                         &gp_mech_krb5, actual_mechs);
        if (ret_maj) {
            goto done;
        }
    }

    if (initiator_time_rec || acceptor_time_rec) {
        ret_maj = gss_inquire_cred_by_mech(&ret_min,
                                           *output_cred_handle,
                                           &gp_mech_krb5,
                                           NULL,
                                           initiator_time_rec,
                                           acceptor_time_rec,
                                           NULL);
        if (ret_maj) {
            goto done;
        }
    }

done:
    if (ret_maj) {
        if (*output_cred_handle) {
            gss_release_cred(&discard, output_cred_handle);
        }
        if (actual_mechs && *actual_mechs) {
            gss_release_oid_set(&discard, actual_mechs);
        }
    }
    *min = ret_min;
    if (ccache) {
        krb5_cc_close(kctx, ccache);
    }
    if (keytab) {
        krb5_kt_close(kctx, keytab);
    }

    krb5_free_context(kctx);
    return ret_maj;
}
