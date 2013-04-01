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
#include "gp_conv.h"

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

#define PWBUFLEN 2048
static char *get_formatted_string(const char *orig, uid_t target_uid)
{
    struct passwd pwd, *res = NULL;
    char buffer[PWBUFLEN];
    int len, left, right;
    char *str;
    char *tmp;
    char *p;
    int ret;

    str = strdup(orig);
    if (!str) {
        return NULL;
    }
    len = strlen(str);

    p = str;
    while ((p = strchr(p, '%')) != NULL) {
        p++;
        switch (*p) {
        case '%':
            left = p - str;
            memmove(p, p + 1, left - 1);
            len--;
            continue;
        case 'U':
            p++;
            left = p - str;
            right = len - left;
            len = asprintf(&tmp, "%.*s%d%s", left - 2, str, target_uid, p);
            safefree(str);
            if (len == -1) {
                goto done;
            }
            str = tmp;
            p = str + (len - right);
            break;
        case 'u':
            if (!res) {
                ret = getpwuid_r(target_uid, &pwd, buffer, 2048, &res);
                if (ret || !res) {
                    safefree(str);
                    goto done;
                }
            }
            p++;
            left = p - str;
            right = len - left;
            len = asprintf(&tmp, "%.*s%s%s", left - 2, str, pwd.pw_name, p);
            safefree(str);
            if (len == -1) {
                goto done;
            }
            str = tmp;
            p = str + (len - right);
            break;
        default:
            GPDEBUG("Invalid format code '%%%c'\n", *p);
            safefree(str);
            goto done;
        }
    }

done:
    return str;
}

#define DEFAULT_CCACHE ""CCACHE_PATH"/krb5cc_%u"
#define DEFAULT_CLIENT_KEYTAB ""VARDIR"lib/gssproxy/clients/%u.keytab"

static int gp_get_cred_environment(struct gp_service *svc,
                                   gssx_name *desired_name,
                                   gss_name_t *requested_name, char **_ccache,
                                   char **_client_keytab, char **_keytab)
{
    gss_name_t name = GSS_C_NO_NAME;
    gss_OID_desc name_type;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uid_t target_uid;
    const char *fmtstr;
    char *ccache = NULL;
    char *client_keytab = NULL;
    char *keytab = NULL;
    int ret = 0;

    target_uid = svc->euid;

    if (desired_name) {
        gp_conv_gssx_to_oid(&desired_name->name_type, &name_type);

        if (svc->trusted &&
            (gss_oid_equal(&name_type, GSS_C_NT_STRING_UID_NAME) ||
             gss_oid_equal(&name_type, GSS_C_NT_MACHINE_UID_NAME))) {
            target_uid = atol(desired_name->display_name.octet_string_val);
        } else {
            ret_maj = gp_conv_gssx_to_name(&ret_min, desired_name, &name);
            if (ret_maj) {
                goto done;
            }
            *requested_name = name;
        }
    }

    if (svc->krb5.ccache == NULL) {
        fmtstr = DEFAULT_CCACHE;
    } else {
        fmtstr = svc->krb5.ccache;
    }
    ccache = get_formatted_string(fmtstr, target_uid);
    if (!ccache) {
        GPDEBUG("Failed to construct ccache string.\n");
        ret = ENOMEM;
        goto done;
    }

    if (svc->krb5.client_keytab == NULL) {
        fmtstr = DEFAULT_CLIENT_KEYTAB;
    } else {
        fmtstr = svc->krb5.client_keytab;
    }
    client_keytab = get_formatted_string(fmtstr, target_uid);
    if (!client_keytab) {
        GPDEBUG("Failed to construct client_keytab string.\n");
        ret = ENOMEM;
        goto done;
    }

    if (svc->krb5.keytab != NULL) {
        fmtstr = svc->krb5.keytab;
        keytab = get_formatted_string(svc->krb5.ccache, target_uid);
    }

    *_ccache = ccache;
    *_client_keytab = client_keytab;
    *_keytab = keytab;

done:
    if (ret) {
        free(ccache);
        free(client_keytab);
        free(keytab);
    }
    return ret;
}

uint32_t gp_add_krb5_creds(uint32_t *min,
                           struct gp_service *svc,
                           gss_cred_id_t in_cred,
                           gssx_name *desired_name,
                           gss_cred_usage_t cred_usage,
                           uint32_t initiator_time_req,
                           uint32_t acceptor_time_req,
                           gss_cred_id_t *output_cred_handle,
                           gss_OID_set *actual_mechs,
                           uint32_t *initiator_time_rec,
                           uint32_t *acceptor_time_rec)
{
    char *ccache_name = NULL;
    char *client_keytab = NULL;
    char *keytab_name = NULL;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uint32_t discard;
    gss_name_t req_name = GSS_C_NO_NAME;
    gss_OID_set_desc desired_mechs = { 1, &gp_mech_krb5 };
    gss_key_value_element_desc cred_elems[3];
    gss_key_value_set_desc cred_store;
    int c;

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

    if (cred_usage == GSS_C_ACCEPT && svc->krb5.keytab == NULL) {
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    ret_min = gp_get_cred_environment(svc, desired_name, &req_name,
                                      &ccache_name, &client_keytab,
                                      &keytab_name);
    if (ret_min) {
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    cred_store.elements = cred_elems;
    c = 0;
    if (ccache_name) {
        cred_elems[c].key = "ccache";
        cred_elems[c].value = ccache_name;
        c++;
    }
    if (client_keytab) {
        cred_elems[c].key = "client_keytab";
        cred_elems[c].value = client_keytab;
        c++;
    }
    if (keytab_name) {
        cred_elems[c].key = "keytab";
        cred_elems[c].value = keytab_name;
        c++;
    }
    cred_store.count = c;

    ret_maj = gss_acquire_cred_from(&ret_min, req_name, GSS_C_INDEFINITE,
                                    &desired_mechs, cred_usage, &cred_store,
                                    output_cred_handle, actual_mechs, NULL);
    if (ret_maj) {
        goto done;
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

    return ret_maj;
}
