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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "gp_proxy.h"
#include "gp_config.h"
#include "gp_selinux.h"

#include <gssapi/gssapi.h>

struct gp_flag_def {
    const char *name;
    uint32_t value;
};

struct gp_flag_def flag_names[] = {
    { "DELEGATE", GSS_C_DELEG_FLAG },
    { "MUTUAL_AUTH", GSS_C_MUTUAL_FLAG },
    { "REPLAY_DETECT", GSS_C_REPLAY_FLAG },
    { "SEQUENCE", GSS_C_SEQUENCE_FLAG },
    { "CONFIDENTIALITY", GSS_C_CONF_FLAG },
    { "INTEGRITIY", GSS_C_INTEG_FLAG },
    { "ANONYMOUS", GSS_C_ANON_FLAG },
    { NULL, 0 }
};

#define DEFAULT_FILTERED_FLAGS GSS_C_DELEG_FLAG
#define DEFAULT_ENFORCED_FLAGS 0

static void free_str_array(const char ***a, int *count)
{
    const char **array;
    int i;

    if (!a) {
        return;
    }
    array = *a;

    if (count) {
        for (i = 0; i < *count; i++) {
            safefree(array[i]);
        }
    } else {
        for (i = 0; array[i]; i++) {
            safefree(array[i]);
        }
    }
    safefree(*a);
}

static void gp_service_free(struct gp_service *svc)
{
    free(svc->name);
    if (svc->mechs & GP_CRED_KRB5) {
        free(svc->krb5.principal);
        free_str_array(&(svc->krb5.cred_store),
                       &svc->krb5.cred_count);
    }
    gp_free_creds_handle(&svc->creds_handle);
    SELINUX_context_free(svc->selinux_ctx);
    memset(svc, 0, sizeof(struct gp_service));
}

static int get_krb5_mech_cfg(struct gp_service *svc,
                             struct gp_ini_context *ctx,
                             const char *secname)
{
    struct { const char *a; const char *b; } deprecated_vals[] = {
        {"krb5_keytab", "keytab" },
        {"krb5_ccache", "ccache" },
        {"krb5_client_keytab", "client_keytab" }
    };
    const char *value;
    int i;
    int ret;

    ret = gp_config_get_string(ctx, secname, "krb5_principal", &value);
    if (ret == 0) {
        svc->krb5.principal = strdup(value);
        if (!svc->krb5.principal) {
            return ENOMEM;
        }
    } else if (ret != ENOENT) {
        return ret;
    }

    /* check for deprecated options */
    for (i = 0; i < 3; i++) {
        ret = gp_config_get_string(ctx, secname, deprecated_vals[i].a, &value);
        if (ret == 0) {
            GPERROR("\"%s = %s\" is deprecated, "
                    "please use \"cred_store = %s:%s\"\n",
                    deprecated_vals[i].a, value,
                    deprecated_vals[i].b, value);
            return EINVAL;
        } else if (ret != ENOENT) {
            return ret;
        }
    }

    /* instead look for the cred_store parameter */
    ret = gp_config_get_string_array(ctx, secname,
                                     "cred_store",
                                     &svc->krb5.cred_count,
                                     &svc->krb5.cred_store);
    if (ret == ENOENT) {
        /* when not there we ignore */
        ret = 0;
    }

    return ret;
}

static int parse_flags(const char *value, uint32_t *storage)
{
    char *handle;
    char *token;
    char *str;
    bool add;
    unsigned long int conv;
    uint32_t flagval;
    int i;

    str = strdup(value);
    if (!str) {
        return ENOMEM;
    }

    for (token = strtok_r(str, ", ", &handle);
         token != NULL;
         token = strtok_r(NULL, ", ", &handle)) {
        switch (token[0]) {
        case '+':
            add = true;
            break;
        case '-':
            add = false;
            break;
        default:
            GPERROR("Ignoring flag [%s], missing +/- qualifier.\n", token);
            continue;
        }
        token++;
        for (i = 0; flag_names[i].name != NULL; i++) {
            if (strcasecmp(token, flag_names[i].name) == 0) {
                flagval = flag_names[i].value;
                break;
            }
        }
        if (flag_names[i].name == NULL) {
            conv = strtoul(token, &handle, 0);
            if (conv == 0 || conv == ULONG_MAX || *handle != '\0') {
                GPERROR("Ignoring flag [%s], unrecognized value.\n", token);
                continue;
            }
            flagval = conv;
        }
        GPDEBUG("%s Flag %s (%u).\n", add?"Add":"Remove", token, flagval);
        if (add) *storage |= flagval;
        else *storage &= ~flagval;
    }
    safefree(str);

    return 0;
}

static int setup_service_creds_handle(struct gp_service *svc)
{
    uint32_t ret_maj, ret_min;

    ret_maj = gp_init_creds_handle(&ret_min, &svc->creds_handle);
    if (ret_maj) {
        return ret_min;
    }

    return 0;
}

static int load_services(struct gp_config *cfg, struct gp_ini_context *ctx)
{
    int num_sec;
    char *secname = NULL;
    const char *value;
    char *vcopy;
    char *token;
    char *handle;
    int valnum;
    int ret;
    int i, n;

    num_sec = gp_config_get_nsec(ctx);

    /* allocate enough space for num_sec services,
     * we won't waste too much space by overallocating */
    cfg->svcs = calloc(num_sec, sizeof(struct gp_service *));
    if (!cfg->svcs) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_sec; i++) {
        secname = gp_config_get_secname(ctx, i);

        ret = strncmp(secname, "service/", 8);
        if (ret == 0) {
            n = cfg->num_svcs;
            cfg->svcs[n] = calloc(1, sizeof(struct gp_service));
            if (!cfg->svcs[n]) {
                ret = ENOMEM;
                goto done;
            }
            cfg->num_svcs++;

            /* by default allow both */
            cfg->svcs[n]->cred_usage = GSS_C_BOTH;

            cfg->svcs[n]->name = strdup(secname + 8);
            if (!cfg->svcs[n]->name) {
                ret = ENOMEM;
                goto done;
            }

            ret = gp_config_get_int(ctx, secname, "euid", &valnum);
            if (ret != 0) {
                /* if euid is missing or there is an error retrieving it
                 * return an error and end. This is a fatal condition. */
                if (ret == ENOENT) {
                    GPERROR("Option 'euid' is missing from [%s].\n", secname);
                    ret = EINVAL;
                }
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                goto done;
            }
            cfg->svcs[n]->euid = valnum;

            ret = gp_config_get_string(ctx, secname, "allow_any_uid", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->any_uid = true;
                }
            }

            ret = gp_config_get_string(ctx, secname, "trusted", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->trusted = true;
                }
            }

            ret = gp_config_get_string(ctx, secname, "kernel_nfsd", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->kernel_nfsd = true;
                }
            }

            ret = gp_config_get_string(ctx, secname, "impersonate", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->impersonate = true;
                }
            }

            ret = gp_config_get_string(ctx, secname, "socket", &value);
            if (ret == 0) {
                cfg->svcs[n]->socket = strdup(value);
                if (!cfg->svcs[n]->socket) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            ret = setup_service_creds_handle(cfg->svcs[n]);
            if (ret) {
                goto done;
            }

            ret = gp_config_get_string(ctx, secname, "mechs", &value);
            if (ret != 0) {
                /* if mechs is missing or there is an error retrieving it
                 * return an error and end. This is a fatal condition. */
                if (ret == ENOENT) {
                    GPERROR("Option 'mechs' is missing from [%s].\n", secname);
                    ret = EINVAL;
                }
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                goto done;
            }

            vcopy = strdup(value);
            if (!vcopy) {
                ret = ENOMEM;
                goto done;
            }
            token = strtok_r(vcopy, ", ", &handle);
            do {

                ret = strcmp(value, "krb5");
                if (ret == 0) {
                    ret = get_krb5_mech_cfg(cfg->svcs[n], ctx, secname);
                    if (ret == 0) {
                        cfg->svcs[n]->mechs |= GP_CRED_KRB5;
                    } else {
                        GPERROR("Failed to read krb5 config for %s.\n",
                                secname);
                        safefree(vcopy);
                        return ret;
                    }
                } else {
                    GPERROR("Unknown mech: %s in [%s], ignoring.\n",
                            token, secname);
                }

                token = strtok_r(NULL, ", ", &handle);
            } while (token != NULL);
            safefree(vcopy);

            if (cfg->svcs[n]->mechs == 0) {
                GPDEBUG("No mechs found for [%s], ignoring.\n", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                continue;
            }

            ret = gp_config_get_string(ctx, secname,
                                       "selinux_context", &value);
            if (ret == 0) {
                cfg->svcs[n]->selinux_ctx = SELINUX_context_new(value);
                if (!cfg->svcs[n]->selinux_ctx) {
                    ret = EINVAL;
                    goto done;
                }
            }

            ret = gp_config_get_string(ctx, secname, "cred_usage", &value);
            if (ret == 0) {
                if (strcasecmp(value, "initiate") == 0) {
                    cfg->svcs[n]->cred_usage = GSS_C_INITIATE;
                } else if (strcasecmp(value, "accept") == 0) {
                    cfg->svcs[n]->cred_usage = GSS_C_ACCEPT;
                } else if (strcasecmp(value, "both") == 0) {
                    cfg->svcs[n]->cred_usage = GSS_C_BOTH;
                } else {
                    GPDEBUG("Invalid value '%s' for cred_usage in [%s].\n",
                            value, secname);
                    ret = EINVAL;
                    goto done;
                }
            }

            cfg->svcs[n]->filter_flags = DEFAULT_FILTERED_FLAGS;
            ret = gp_config_get_string(ctx, secname, "filter_flags", &value);
            if (ret == 0) {
                parse_flags(value, &cfg->svcs[n]->filter_flags);
            }

            cfg->svcs[n]->enforce_flags = DEFAULT_ENFORCED_FLAGS;
            ret = gp_config_get_string(ctx, secname, "enforce_flags", &value);
            if (ret == 0) {
                ret = parse_flags(value, &cfg->svcs[n]->enforce_flags);
                if (ret) goto done;
            }
        }
        safefree(secname);
    }

    if (cfg->num_svcs == 0) {
        GPERROR("No service sections configured!\n");
        return ENOENT;
    }

    ret = 0;

done:
    safefree(secname);
    return ret;
}

static int gp_init_ini_context(const char *config_file,
                               struct gp_ini_context **ctxp)
{
    struct gp_ini_context *ctx;
    int ret;

    if (!ctxp) {
        return EINVAL;
    }

    ctx = calloc(1, sizeof(struct gp_ini_context));
    if (!ctx) {
        return ENOENT;
    }

    ret = gp_config_init(config_file, ctx);

    if (ret) {
        free(ctx);
    } else {
        *ctxp = ctx;
    }
    return ret;
}

int load_config(struct gp_config *cfg)
{
    struct gp_ini_context *ctx;
    const char *tmpstr;
    int ret;

    ret = gp_init_ini_context(cfg->config_file, &ctx);
    if (ret) {
        return ret;
    }

    ret = gp_config_get_string(ctx, "gssproxy", "debug", &tmpstr);
    if (ret == 0) {
        if (gp_boolean_is_true(tmpstr)) {
            gp_debug_enable();
        }
    } else if (ret != ENOENT) {
        goto done;
    }

    ret = gp_config_get_string(ctx, "gssproxy", "run_as_user", &tmpstr);
    if (ret == 0) {
        cfg->proxy_user = strdup(tmpstr);
        if (!cfg->proxy_user) {
            ret = ENOMEM;
            goto done;
        }
    } else if (ret != ENOENT) {
        goto done;
    }

    ret = gp_config_get_int(ctx, "gssproxy", "worker threads",
                            &cfg->num_workers);
    if (ret != 0 && ret != ENOENT) {
        goto done;
    }

    ret = load_services(cfg, ctx);

done:
    if (ret != 0) {
        GPERROR("Error reading configuration %d: %s", ret, gp_strerror(ret));
    }
    gp_config_close(ctx);
    safefree(ctx);
    return ret;
}

struct gp_config *read_config(char *config_file, char *socket_name,
                              int opt_daemonize)
{
    const char *socket = GP_SOCKET_NAME;
    struct gp_config *cfg;
    int ret;

    cfg = calloc(1, sizeof(struct gp_config));
    if (!cfg) {
        return NULL;
    }

    if (config_file) {
        cfg->config_file = strdup(config_file);
        if (!cfg->config_file) {
            free(cfg);
            return NULL;
        }
    } else {
        ret = asprintf(&cfg->config_file, "%s/gssproxy.conf", PUBCONF_PATH);
        if (ret == -1) {
            free(cfg);
            return NULL;
        }
    }

    if (socket_name) socket = socket_name;

    cfg->socket_name = strdup(socket);
    if (cfg->socket_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    switch (opt_daemonize) {
    case 0:
        /* daemonize by default */
    case 1:
        cfg->daemonize = true;
        break;
    case 2:
        cfg->daemonize = false;
        break;
    }

    ret = load_config(cfg);
    if (ret) {
        GPDEBUG("Config file not found!\n");
    }

done:
    if (ret) {
        free_config(&cfg);
    }

    return cfg;
}

struct gp_creds_handle *gp_service_get_creds_handle(struct gp_service *svc)
{
    return svc->creds_handle;
}

void free_config(struct gp_config **cfg)
{
    struct gp_config *config = *cfg;
    uint32_t i;

    if (!config) {
        return;
    }

    free(config->config_file);
    free(config->socket_name);
    free(config->proxy_user);

    for (i=0; i < config->num_svcs; i++) {
        gp_service_free(config->svcs[i]);
        safefree(config->svcs[i]);
    }

    free(config->svcs);
    free(config);
    *cfg = NULL;
}

#ifdef WITH_INIPARSER
#include "gp_config_iniparser.h"

int gp_config_init(const char *config_file,
                   struct gp_ini_context *ctx)
{
    return gp_iniparser_init(config_file, ctx);
}

int gp_config_get_string(struct gp_ini_context *ctx,
                         const char *secname,
                         const char *keyname,
                         char **value)
{
    return gp_iniparser_get_string(ctx, secname, keyname, value);
}

int gp_config_get_string_array(struct gp_ini_context *ctx,
                               const char *secname,
                               const char *keyname,
                               int *num_values,
                               char ***values)
{
    return ENOENT;
}

int gp_config_get_int(struct gp_ini_context *ctx,
                      const char *secname,
                      const char *keyname,
                      int *value)
{
    return gp_iniparser_get_int(ctx, secname, keyname, value);
}

int gp_config_get_nsec(struct gp_ini_context *ctx)
{
    return gp_iniparser_get_nsec(ctx);
}

char *gp_config_get_secname(struct gp_ini_context *ctx,
                            int i)
{
    return gp_iniparser_get_secname(ctx, i);
}

int gp_config_close(struct gp_ini_context *ctx)
{
    return gp_iniparser_close(ctx);
}

#endif /* WITH_INIPARSER */

#ifdef WITH_DINGLIBS
#include "gp_config_dinglibs.h"

int gp_config_init(const char *config_file,
                   struct gp_ini_context *ctx)
{
    return gp_dinglibs_init(config_file, ctx);
}

int gp_config_get_string(struct gp_ini_context *ctx,
                         const char *secname,
                         const char *keyname,
                         const char **value)
{
    return gp_dinglibs_get_string(ctx, secname, keyname, value);
}

int gp_config_get_string_array(struct gp_ini_context *ctx,
                               const char *secname,
                               const char *keyname,
                               int *num_values,
                               const char ***values)
{
    return gp_dinglibs_get_string_array(ctx, secname, keyname,
                                        num_values, values);
}

int gp_config_get_int(struct gp_ini_context *ctx,
                      const char *secname,
                      const char *keyname,
                      int *value)
{
    return gp_dinglibs_get_int(ctx, secname, keyname, value);
}

int gp_config_get_nsec(struct gp_ini_context *ctx)
{
    return gp_dinglibs_get_nsec(ctx);
}

char *gp_config_get_secname(struct gp_ini_context *ctx,
                            int i)
{
    return gp_dinglibs_get_secname(ctx, i);
}

int gp_config_close(struct gp_ini_context *ctx)
{
    return gp_dinglibs_close(ctx);
}

#endif /* WITH_DINGLIBS */
