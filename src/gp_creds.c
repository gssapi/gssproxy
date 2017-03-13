/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <krb5/krb5.h>
#include <gssapi/gssapi_krb5.h>
#include "gp_proxy.h"
#include "gp_rpc_creds.h"
#include "gp_creds.h"
#include "gp_conv.h"
#include "gp_export.h"

#define GSS_MECH_KRB5_OID_LENGTH 9
#define GSS_MECH_KRB5_OID "\052\206\110\206\367\022\001\002\002"

gss_OID_desc gp_mech_krb5 = { GSS_MECH_KRB5_OID_LENGTH,
                              discard_const(GSS_MECH_KRB5_OID) };

struct supported_mechs_map {
    int internal_id;
    const gss_OID mech;
} supported_mechs_map[] = {
    { GP_CRED_KRB5, &gp_mech_krb5 },
    { 0, NULL }
};

bool gp_creds_allowed_mech(struct gp_call_ctx *gpcall, gss_OID desired_mech)
{
    int i;

    for (i = 0; supported_mechs_map[i].internal_id != 0; i++) {
        if (gpcall->service->mechs & supported_mechs_map[i].internal_id) {
            if (gss_oid_equal(desired_mech, supported_mechs_map[i].mech)) {
                return true;
            }
        }
    }

    return false;
}

uint32_t gp_get_supported_mechs(uint32_t *min, gss_OID_set *set)
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
    const char *socket;
    int i;

    gcs = gp_conn_get_creds(conn);
    socket = gp_conn_get_socket(conn);

    for (i = 0; i < gpctx->config->num_svcs; i++) {
        if (gpctx->config->svcs[i]->any_uid ||
            gpctx->config->svcs[i]->euid == gcs->ucred.uid) {
            if (gpctx->config->svcs[i]->socket) {
                if (!gp_same(socket, gpctx->config->svcs[i]->socket)) {
                    continue;
                }
            } else {
                if (!gp_same(socket, gpctx->config->socket_name)) {
                    continue;
                }
            }
            if (!gp_conn_check_selinux(conn,
                                       gpctx->config->svcs[i]->selinux_ctx)) {
                continue;
            }
            return gpctx->config->svcs[i];
        }
    }

    return NULL;
}

#define PWBUFLEN 2048
static char *uid_to_name(uid_t uid)
{
    struct passwd pwd, *res = NULL;
    char buffer[PWBUFLEN];
    int ret;

    ret = getpwuid_r(uid, &pwd, buffer, PWBUFLEN, &res);
    if (ret || !res) {
        return NULL;
    }
    return strdup(pwd.pw_name);
}

static char *get_formatted_string(const char *orig, uid_t target_uid)
{
    int len, left, right;
    char *user = NULL;
    char *str;
    char *tmp;
    char *p;

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
            if (!user) {
                user = uid_to_name(target_uid);
                if (!user) {
                    safefree(str);
                    goto done;
                }
            }
            p++;
            left = p - str;
            right = len - left;
            len = asprintf(&tmp, "%.*s%s%s", left - 2, str, user, p);
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
    safefree(user);
    return str;
}

int gp_get_acquire_type(struct gssx_arg_acquire_cred *arg)
{
    struct gssx_option *val = NULL;

    gp_options_find(val, arg->options,
                    ACQUIRE_TYPE_OPTION, sizeof(ACQUIRE_TYPE_OPTION));
    if (val) {
        if (gp_option_value_match(val, ACQUIRE_IMPERSONATE_NAME,
                                  sizeof(ACQUIRE_IMPERSONATE_NAME))) {
            return ACQ_IMPNAME;
        } else {
            return -1;
        }
    }

    return ACQ_NORMAL;
}

static bool try_impersonate(struct gp_service *svc,
                            gss_cred_usage_t cred_usage,
                            enum gp_aqcuire_cred_type acquire_type)
{
    if (acquire_type == ACQ_IMPNAME &&
        (svc->allow_proto_trans || svc->trusted)) {
        return true;
    }
    if (svc->impersonate &&
        (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH)) {
        return true;
    }

    return false;
}

static void safe_free_mem_ccache(void *data)
{
    krb5_error_code e;
    krb5_context ctx = NULL;
    krb5_ccache cc = NULL;
    char *ccname = (char *) data;

    if (!ccname) {
        return;
    }

    e = krb5_init_context(&ctx);
    if (e != 0) {
        goto done;
    }

    e = krb5_cc_resolve(ctx, ccname, &cc);
    if (e != 0) {
        goto done;
    }

    /* also closes handle */
    krb5_cc_destroy(ctx, cc);

done:
    if (ctx) {
        krb5_free_context(ctx);
    }
    free(ccname);
}

static int ensure_segregated_ccache(struct gp_call_ctx *gpcall,
                                    int cc_num,
                                    struct gp_service *svc,
                                    gss_key_value_set_desc *cs)
{
    int ret;
    char *buf;
    pid_t tid = -1;

    if (cc_num != -1) {
        return 0;
    }

    /* We always have space for at least 1 more entry in cs. */
    cc_num = cs->count;

    cs->elements[cc_num].key = strdup("ccache");
    if (!cs->elements[cc_num].key) {
        return ENOMEM;
    }

    do {
        errno = 0;
        tid = syscall(SYS_gettid);
    } while (tid == -1 && errno == EINTR);

    ret = asprintf(&buf, "MEMORY:internal_%d", tid);
    if (ret == -1) {
        return ENOMEM;
    }

    gpcall->destroy_callback = safe_free_mem_ccache;
    gpcall->destroy_callback_data = buf;

    cs->elements[cc_num].value = strdup(buf);
    if (!cs->elements[cc_num].value) {
        return ENOMEM;
    }

    cs->count = cc_num + 1;

    return 0;
}

static int gp_get_cred_environment(struct gp_call_ctx *gpcall,
                                   gssx_name *desired_name,
                                   gss_name_t *requested_name,
                                   gss_cred_usage_t *cred_usage,
                                   gss_key_value_set_desc *cs)
{
    struct gp_service *svc;
    gss_name_t name = GSS_C_NO_NAME;
    gss_buffer_desc namebuf;
    gss_OID_desc name_type;
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uid_t target_uid;
    bool user_requested = false;
    bool use_service_keytab = false;
    int ret = -1;
    int k_num = -1;
    int ck_num = -1;
    int cc_num = -1;
    int d;

    memset(cs, 0, sizeof(gss_key_value_set_desc));

    target_uid = gp_conn_get_uid(gpcall->connection);
    svc = gpcall->service;

    /* filter based on cred_usage */
    if (svc->cred_usage != GSS_C_BOTH) {
        if (*cred_usage == GSS_C_BOTH) {
            *cred_usage = svc->cred_usage;
        } else if (svc->cred_usage != *cred_usage) {
            ret = EACCES;
            goto done;
        }
    }

    if (desired_name) {
        gp_conv_gssx_to_oid(&desired_name->name_type, &name_type);

        /* A service retains the trusted flag only if the current uid matches
         * the configured euid */
        if (svc->trusted &&
            (svc->euid == target_uid) &&
            (gss_oid_equal(&name_type, GSS_C_NT_STRING_UID_NAME) ||
             gss_oid_equal(&name_type, GSS_C_NT_MACHINE_UID_NAME))) {
            target_uid = atol(desired_name->display_name.octet_string_val);
            user_requested = true;
        } else {
            /* it's a user request if it comes from an arbitrary uid */
            if (svc->euid != target_uid) {
                user_requested = true;
            } else {
                use_service_keytab = true;
            }
            ret_maj = gp_conv_gssx_to_name(&ret_min, desired_name, &name);
            if (ret_maj) {
                goto done;
            }
            *requested_name = name;
        }
    } else {
        /* No name provided */
        if (svc->trusted && (svc->euid == target_uid)) {
            use_service_keytab = true;
        } else if (svc->euid != target_uid) {
            user_requested = true;
        }
    }

    /* impersonation case (only for initiation) */
    if (user_requested) {
        if (try_impersonate(svc, *cred_usage, ACQ_NORMAL)) {
            char *str;
            /* When impersonating we want to use the service keytab to
             * acquire initial credential ... */
            use_service_keytab = true;

            /* ... and after that make the s4u2self delegation dance with the
             * target name identifying the user */
            str = uid_to_name(target_uid);
            if (str == NULL) {
                GPERROR("Failed to get username from uid %d\n", target_uid);
                return ENOENT;
            }
            namebuf.value = str;
            namebuf.length = strlen(str);
            ret_maj = gss_import_name(&ret_min, &namebuf,
                                      GSS_C_NT_USER_NAME, requested_name);
            if (ret_maj) {
                GPERROR("Failed to import username %s\n", str);
                safefree(str);
                return ENOMEM;
            }
            safefree(str);
        }
    }

    if (use_service_keytab &&
        (*requested_name == GSS_C_NO_NAME) && (svc->krb5.principal)) {
        /* configuration dictates to use a specific name */
        gss_buffer_desc const_buf;
        const_buf.value = svc->krb5.principal;
        const_buf.length = strlen(svc->krb5.principal) + 1;

        ret_maj = gss_import_name(&ret_min, &const_buf,
                                  discard_const(GSS_KRB5_NT_PRINCIPAL_NAME),
                                  requested_name);
        if (ret_maj) {
            GPERROR("Failed to import krb5_principal name %s\n",
                    svc->krb5.principal);
            goto done;
        }
    }

    if (svc->krb5.store.count == 0) {
        return 0;
    }

    /* allocate 2 more than in source, just in case we need to add
     * an internal client_keytab element and ccache */
    cs->elements = calloc(svc->krb5.store.count + 2,
                          sizeof(gss_key_value_element_desc));
    if (!cs->elements) {
        ret = ENOMEM;
        goto done;
    }
    for (d = 0; d < svc->krb5.store.count; d++) {
        if (strcmp(svc->krb5.store.elements[d].key, "client_keytab") == 0) {
            ck_num = cs->count;
        } else if (strcmp(svc->krb5.store.elements[d].key, "keytab") == 0) {
            k_num = cs->count;
        } else if (strcmp(svc->krb5.store.elements[d].key, "ccache") == 0) {
            cc_num = cs->count;
        }

        cs->elements[cs->count].key = strdup(svc->krb5.store.elements[d].key);
        if (!cs->elements[cs->count].key) {
            ret = ENOMEM;
            goto done;
        }

        cs->elements[cs->count].value =
            get_formatted_string(svc->krb5.store.elements[d].value,
                                 target_uid);
        if (!cs->elements[cs->count].value) {
            safefree(cs->elements[cs->count].key);
            GPDEBUG("Failed to build credential store formatted string.\n");
            ret = ENOMEM;
            goto done;
        }

        cs->count++;
    }

    /* when a user is not explicitly requested then it means the calling
     * application wants to use the credentials in the standard keytab,
     * if any. */
    if (use_service_keytab) {
        if (k_num == -1) {
            if (ck_num == -1) {
                ret = EINVAL;
            } else {
                /* allow a service to define only the client keytab */
                ret = 0;
            }
            goto done;
        }
        if (ck_num == -1) {
            /* we always have space for 1 more */
            ck_num = cs->count;

            cs->elements[ck_num].key = strdup("client_keytab");
            if (!cs->elements[ck_num].key) {
                ret = ENOMEM;
                goto done;
            }

            cs->count = ck_num + 1;
        } else {
            safefree(cs->elements[ck_num].value);
        }
        cs->elements[ck_num].value = strdup(cs->elements[k_num].value);
        if (!cs->elements[ck_num].value) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = ensure_segregated_ccache(gpcall, cc_num, svc, cs);
    if (ret != 0) {
        goto done;
    }

    ret = 0;

done:
    if (ret) {
        free_cred_store_elements(cs);
    }
    return ret;
}

static uint32_t gp_check_cred(uint32_t *min,
                              gss_cred_id_t in_cred,
                              gssx_name *desired_name,
                              gss_cred_usage_t cred_usage)
{
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uint32_t discard;
    uint32_t i;
    gss_name_t req_name = GSS_C_NO_NAME;
    gss_name_t check_name = GSS_C_NO_NAME;
    gss_OID_set mechanisms = GSS_C_NO_OID_SET;
    gss_cred_usage_t usage;
    uint32_t lifetime;
    int present = 0;

    ret_maj = gss_inquire_cred(&ret_min, in_cred,
                               desired_name?&check_name:NULL,
                               &lifetime, &usage, &mechanisms);
    if (ret_maj) {
        goto done;
    }

    for (i = 0; i < mechanisms->count; i++) {
        present = gss_oid_equal(&mechanisms->elements[i], gss_mech_krb5);
        if (present) break;
    }
    if (!present) {
        ret_maj = GSS_S_CRED_UNAVAIL;
        goto done;
    }

    if (desired_name) {
        int equal;
        ret_maj = gp_conv_gssx_to_name(&ret_min, desired_name, &req_name);
        if (ret_maj) {
            goto done;
        }
        ret_maj = gss_compare_name(&ret_min, req_name, check_name, &equal);
        if (ret_maj) {
            goto done;
        }
        if (!equal) {
            ret_maj = GSS_S_CRED_UNAVAIL;
            goto done;
        }
    }

    switch (cred_usage) {
    case GSS_C_ACCEPT:
        if (usage == GSS_C_INITIATE) {
            ret_maj = GSS_S_NO_CRED;
            goto done;
        }
        break;
    case GSS_C_INITIATE:
        if (usage == GSS_C_ACCEPT) {
            ret_maj = GSS_S_NO_CRED;
            goto done;
        }
        break;
    case GSS_C_BOTH:
        if (usage != GSS_C_BOTH) {
            ret_maj = GSS_S_NO_CRED;
            goto done;
        }
        break;
    }

    if (lifetime == 0) {
        ret_maj = GSS_S_CREDENTIALS_EXPIRED;
    } else {
        ret_maj = GSS_S_COMPLETE;
    }

done:
    gss_release_oid_set(&discard, &mechanisms);
    gss_release_name(&discard, &check_name);
    gss_release_name(&discard, &req_name);

    *min = ret_min;
    return ret_maj;
}


uint32_t gp_add_krb5_creds(uint32_t *min,
                           struct gp_call_ctx *gpcall,
                           enum gp_aqcuire_cred_type acquire_type,
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
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    uint32_t discard;
    gss_name_t req_name = GSS_C_NO_NAME;
    gss_OID_set_desc desired_mechs = { 1, &gp_mech_krb5 };
    gss_key_value_set_desc cred_store = { 0 };
    gss_cred_id_t impersonator_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t user_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t acceptor_context = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc init_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc accept_token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t input_cred;

    if (!min || !output_cred_handle) {
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    *min = 0;
    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs) {
        *actual_mechs = GSS_C_NO_OID_SET;
    }

    if (in_cred != GSS_C_NO_CREDENTIAL && acquire_type != ACQ_IMPNAME) {
        /* NOTE: we can't yet handle adding to an existing credential due
         * to the way gss_krb5_import_cred works. This limitation should
         * be removed by adding a gssapi extension that superceedes this
         * function completely */

        /* just check if it is a valid krb5 cred */
        ret_maj = gp_check_cred(&ret_min, in_cred, desired_name, cred_usage);
        if (ret_maj == GSS_S_COMPLETE) {
            return GSS_S_COMPLETE;
        } else if (ret_maj == GSS_S_CREDENTIALS_EXPIRED ||
                   ret_maj == GSS_S_NO_CRED) {
            /* continue and try to obtain new creds */
            ret_maj = 0;
            ret_min = 0;
        } else {
            *min = ret_min;
            return GSS_S_CRED_UNAVAIL;
        }
    }

    if (acquire_type == ACQ_NORMAL) {
        ret_min = gp_get_cred_environment(gpcall, desired_name, &req_name,
                                          &cred_usage, &cred_store);
        if (ret_min) {
            ret_maj = GSS_S_CRED_UNAVAIL;
        }
    } else if (desired_name) {
        ret_maj = gp_conv_gssx_to_name(&ret_min, desired_name, &req_name);
    }
    if (ret_maj) {
        goto done;
    }

    if (!try_impersonate(gpcall->service, cred_usage, acquire_type)) {
        ret_maj = gss_acquire_cred_from(&ret_min, req_name, GSS_C_INDEFINITE,
                                        &desired_mechs, cred_usage,
                                        &cred_store, output_cred_handle,
                                        actual_mechs, NULL);
        if (ret_maj) {
            goto done;
        }
    } else { /* impersonation */
        switch (acquire_type) {
        case ACQ_NORMAL:
            ret_maj = gss_acquire_cred_from(&ret_min, GSS_C_NO_NAME,
                                            GSS_C_INDEFINITE,
                                            &desired_mechs, GSS_C_BOTH,
                                            &cred_store, &impersonator_cred,
                                            NULL, NULL);
            if (ret_maj) {
                goto done;
            }
            input_cred = impersonator_cred;
            break;
        case ACQ_IMPNAME:
            input_cred = in_cred;
            break;
        default:
            ret_maj = GSS_S_FAILURE;
            ret_min = EFAULT;
            goto done;
        }

        ret_maj = gss_inquire_cred(&ret_min, input_cred,
                                   &target_name, NULL, NULL, NULL);
        if (ret_maj) {
            goto done;
        }

        ret_maj = gss_acquire_cred_impersonate_name(&ret_min,
                                                    input_cred,
                                                    req_name,
                                                    GSS_C_INDEFINITE,
                                                    &desired_mechs,
                                                    GSS_C_INITIATE,
                                                    &user_cred,
                                                    actual_mechs, NULL);
        if (ret_maj) {
            goto done;
        }

        if (acquire_type == ACQ_IMPNAME) {
            /* we are done here */
            *output_cred_handle = user_cred;
            user_cred = GSS_C_NO_CREDENTIAL;
            goto done;
        }

        /* now acquire credentials for impersonated user to self */
        ret_maj = gss_init_sec_context(&ret_min, user_cred, &initiator_context,
                                       target_name, &gp_mech_krb5,
                                       GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG,
                                       GSS_C_INDEFINITE,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       GSS_C_NO_BUFFER, NULL,
                                       &init_token, NULL, NULL);
        if (ret_maj) {
            goto done;
        }
        /* accept context to be able to store delegated credentials */
        ret_maj = gss_accept_sec_context(&ret_min, &acceptor_context,
                                         input_cred, &init_token,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         NULL, NULL, &accept_token,
                                         NULL, NULL, output_cred_handle);
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
        gp_log_status(&gp_mech_krb5, ret_maj, ret_min);

        if (*output_cred_handle) {
            gss_release_cred(&discard, output_cred_handle);
        }
        if (actual_mechs && *actual_mechs) {
            gss_release_oid_set(&discard, actual_mechs);
        }
    }
    free_cred_store_elements(&cred_store);
    gss_release_cred(&discard, &impersonator_cred);
    gss_release_cred(&discard, &user_cred);
    gss_release_name(&discard, &target_name);
    gss_delete_sec_context(&discard, &initiator_context, NULL);
    gss_release_buffer(&discard, &init_token);
    gss_release_buffer(&discard, &accept_token);
    gss_release_name(&discard, &req_name);
    *min = ret_min;

    return ret_maj;
}

void gp_filter_flags(struct gp_call_ctx *gpcall, uint32_t *flags)
{
    *flags |= gpcall->service->enforce_flags;
    *flags &= ~gpcall->service->filter_flags;
}

uint32_t gp_cred_allowed(uint32_t *min,
                         struct gp_call_ctx *gpcall,
                         gss_cred_id_t cred)
{
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    char *memcache = NULL;
    krb5_context context = NULL;
    krb5_ccache ccache = NULL;
    krb5_data config;
    int err;

    if (cred == GSS_C_NO_CREDENTIAL) {
        return GSS_S_CRED_UNAVAIL;
    }

    if (gpcall->service->trusted ||
        gpcall->service->impersonate ||
        gpcall->service->allow_const_deleg) {

        GPDEBUGN(2, "Credentials allowed by configuration\n");
        *min = 0;
        return GSS_S_COMPLETE;
    }

    /* FIXME: krb5 specific code, should get an oid registerd to query the
     * cred with gss_inquire_cred_by_oid() or similar instead */

    err = krb5_init_context(&context);
    if (err) {
        ret_min = err;
        ret_maj =  GSS_S_FAILURE;
        goto done;
    }

    /* Create a memory ccache we can iterate with libkrb5 functions */
    gss_key_value_element_desc ccelement = { "ccache", NULL };
    gss_key_value_set_desc cred_store = { 1, &ccelement };

    err = asprintf(&memcache, "MEMORY:cred_allowed_%p", &memcache);
    if (err == -1) {
        memcache = NULL;
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    cred_store.elements[0].value = memcache;

    ret_maj = gss_store_cred_into(&ret_min, cred, GSS_C_INITIATE,
                                  discard_const(gss_mech_krb5), 1, 0,
                                  &cred_store, NULL, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        goto done;
    }

    err = krb5_cc_resolve(context, memcache, &ccache);
    if (err) {
        ret_min = err;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    /* if we find an impersonator entry we bail as that is not authorized,
     * if it were then gpcall->service->allow_const_deleg would have caused
     * the ealier check to return GSS_S_COMPLETE already */
    err = krb5_cc_get_config(context, ccache, NULL, "proxy_impersonator",
                             &config);
    if (!err) {
        krb5_free_data_contents(context, &config);
        ret_min = 0;
        ret_maj = GSS_S_UNAUTHORIZED;
    } else if (err != KRB5_CC_NOTFOUND) {
        ret_min = err;
        ret_maj = GSS_S_FAILURE;
    } else {
        ret_min = 0;
        ret_maj = GSS_S_COMPLETE;
    }

done:
    switch (ret_maj) {
    case GSS_S_UNAUTHORIZED:
        GPDEBUGN(2, "Unauthorized impersonator credentials detected\n");
        break;
    case GSS_S_COMPLETE:
        GPDEBUGN(2, "No impersonator credentials detected\n");
        break;
    default:
        GPDEBUG("Failure while checking credentials\n");
        break;
    }
    if (context) {
        /* NOTE: destroy only if we created a MEMORY ccache */
        if (ccache) {
            if (memcache) krb5_cc_destroy(context, ccache);
            else krb5_cc_close(context, ccache);
        }
        krb5_free_context(context);
    }
    free(memcache);
    *min = ret_min;
    return ret_maj;
}

uint32_t gp_count_tickets(uint32_t *min, gss_cred_id_t cred, uint32_t *ccsum)
{
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    char *memcache = NULL;
    krb5_context context = NULL;
    krb5_ccache ccache = NULL;
    krb5_cc_cursor cursor = NULL;
    krb5_creds creds;
    int err;

    err = krb5_init_context(&context);
    if (err != 0) {
        ret_min = err;
        ret_maj =  GSS_S_FAILURE;
        goto done;
    }

    /* Create a memory ccache we can iterate with libkrb5 functions */
    gss_key_value_element_desc ccelement = { "ccache", NULL };
    gss_key_value_set_desc cred_store = { 1, &ccelement };

    err = asprintf(&memcache, "MEMORY:cred_allowed_%p", &memcache);
    if (err == -1) {
        memcache = NULL;
        ret_min = ENOMEM;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    cred_store.elements[0].value = memcache;

    ret_maj = gss_store_cred_into(&ret_min, cred, GSS_C_INITIATE,
                                  discard_const(gss_mech_krb5), 1, 0,
                                  &cred_store, NULL, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        goto done;
    }

    err = krb5_cc_resolve(context, memcache, &ccache);
    if (err != 0) {
        ret_min = err;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    err = krb5_cc_start_seq_get(context, ccache, &cursor);
    if (err != 0) {
        ret_min = err;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    do {
        err = krb5_cc_next_cred(context, ccache, &cursor, &creds);
        if (err != 0 && err != KRB5_CC_END) {
            ret_min = err;
            ret_maj = GSS_S_FAILURE;
            goto done;
        }

        /* TODO: Should we do a real checksum over all creds->ticket data and
         * flags in future ? */
        (*ccsum)++;

    } while (err == 0);

    err = krb5_cc_end_seq_get(context, ccache, &cursor);
    if (err != 0) {
        ret_min = err;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

done:
    if (context) {
        /* NOTE: destroy only if we created a MEMORY ccache */
        if (ccache) {
            if (memcache) {
                krb5_cc_destroy(context, ccache);
            } else {
                krb5_cc_close(context, ccache);
            }
        }
        krb5_free_context(context);
    }
    free(memcache);
    *min = ret_min;
    return ret_maj;
}

/* Check if cred refresh is being requested by the client.
 * if so, take a snapshot of the cred so that later we can check if anything
 * was added */
uint32_t gp_check_sync_creds(struct gp_cred_check_handle *h,
                             gss_cred_id_t cred)
{
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    struct gp_service *svc = h->ctx->service;
    struct gssx_option *opt = NULL;
    uint32_t ccsum = 0;

    if (!svc->allow_cc_sync)
        return 0;

    gp_options_find(opt, h->options, CRED_SYNC_OPTION,
                    sizeof(CRED_SYNC_OPTION));
    if (!opt) {
        return 0;
    }
    if (!gpopt_string_match(&opt->value, CRED_SYNC_DEFAULT,
                            sizeof(CRED_SYNC_DEFAULT))) {
        return 0;
    }

    for (size_t i = 0; i < svc->krb5.store.count; i++) {
        if (strcmp(svc->krb5.store.elements[i].key, "ccache") == 0) {
            /* Saving in local ccache no need to sync up to client */
            return 0;
        }
    }

    ret_maj = gp_count_tickets(&ret_min, cred, &ccsum);
    if (ret_maj) {
        return 0;
    }

    return ccsum;
}

uint32_t gp_export_sync_creds(uint32_t *min, struct gp_call_ctx *gpcall,
                              gss_cred_id_t *cred,
                              gssx_option **options_val, u_int *options_len)
{
    uint32_t ret_maj = 0;
    uint32_t ret_min = 0;
    gssx_cred creds = { 0 };
    char value[GPKRB_MAX_CRED_SIZE];
    size_t len;
    XDR xdrctx;
    bool xdrok;

    ret_maj = gp_export_gssx_cred(&ret_min, gpcall, cred, &creds);
    if (ret_maj) {
        goto done;
    }

    xdrmem_create(&xdrctx, value, GPKRB_MAX_CRED_SIZE, XDR_ENCODE);
    xdrok = xdr_gssx_cred(&xdrctx, &creds);
    if (!xdrok) {
        ret_min = ENOSPC;
        ret_maj = GSS_S_FAILURE;
        goto done;
    }
    len = xdr_getpos(&xdrctx);

    ret_min = gp_add_option(options_val, options_len, CRED_SYNC_PAYLOAD,
                            sizeof(CRED_SYNC_PAYLOAD), value, len);
    if (ret_min) {
        ret_maj = GSS_S_FAILURE;
        goto done;
    }

    ret_min = 0;
    ret_maj = GSS_S_COMPLETE;

done:
    xdr_free((xdrproc_t)xdr_gssx_cred, (char *)&creds);
    *min = ret_min;
    return ret_maj;
}
