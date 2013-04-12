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

static void free_str_array(char ***a)
{
    char **array = *a;
    int i;

    if (!a) {
        return;
    }
    for (i = 0; array[i]; i++) {
        safefree(array[i]);
    }
    safefree(*a);
}

static void gp_service_free(struct gp_service *svc)
{
    free(svc->name);
    if (svc->mechs & GP_CRED_KRB5) {
        free(svc->krb5.principal);
        free_str_array(&(svc->krb5.cred_store));
    }
    gp_free_creds_handle(&svc->creds_handle);
    memset(svc, 0, sizeof(struct gp_service));
}

static bool option_is_set(const char *s)
{
    if (strcasecmp(s, "1") == 0 ||
        strcasecmp(s, "on") == 0 ||
        strcasecmp(s, "true") == 0 ||
        strcasecmp(s, "yes") == 0) {
        return true;
    }

    return false;
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
    char *value;
    int i;

    value = gp_config_get_string(ctx, secname, "krb5_principal");
    if (value) {
        svc->krb5.principal = strdup(value);
        if (!svc->krb5.principal) {
            return ENOMEM;
        }
    }

    /* check for deprecated options */
    for (i = 0; i < 3; i++) {
        value = gp_config_get_string(ctx, secname, deprecated_vals[i].a);
        if (value) {
            GPERROR("\"%s = %s\" is deprecated, "
                    "please use \"cred_store = %s:%s\"\n",
                    deprecated_vals[i].a, value,
                    deprecated_vals[i].b, value);
            return EINVAL;
        }
    }

    svc->krb5.cred_store = gp_config_get_string_array(ctx, secname,
                                                      "cred_store",
                                                      &svc->krb5.cred_count);

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
    char *value;
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

            cfg->svcs[n]->name = strdup(secname + 8);
            if (!cfg->svcs[n]->name) {
                ret = ENOMEM;
                goto done;
            }

            valnum = gp_config_get_int(ctx, secname, "euid");
            if (valnum == -1) {
                /* malformed section, mech is missing */
                GPDEBUG("Euid missing from [%s], ignoring.\n", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                continue;
            }
            cfg->svcs[n]->euid = valnum;

            value = gp_config_get_string(ctx, secname, "trusted");
            if (value != NULL) {
                if (option_is_set(value)) {
                    cfg->svcs[n]->trusted = true;
                }
            }

            value = gp_config_get_string(ctx, secname, "kernel_nfsd");
            if (value != NULL) {
                if (option_is_set(value)) {
                    cfg->svcs[n]->kernel_nfsd = true;
                }
            }

            value = gp_config_get_string(ctx, secname, "socket");
            if (value != NULL) {
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

            value = gp_config_get_string(ctx, secname, "mechs");
            if (value == NULL) {
                /* malformed section, mech is missing */
                GPDEBUG("Mechs missing from [%s], ignoring.\n", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                continue;
            }

            token = strtok_r(value, ", ", &handle);
            do {

                ret = strcmp(value, "krb5");
                if (ret == 0) {
                    ret = get_krb5_mech_cfg(cfg->svcs[n], ctx, secname);
                    if (ret == 0) {
                        cfg->svcs[n]->mechs |= GP_CRED_KRB5;
                    } else {
                        GPDEBUG("Failed to read krb5 config for %s, ignoring.\n",
                                secname);
                    }
                } else {
                    GPDEBUG("Unknown mech: %s in [%s], ignoring.\n",
                            token, secname);
                }

                token = strtok_r(NULL, ", ", &handle);
            } while (token != NULL);

            if (cfg->svcs[n]->mechs == 0) {
                GPDEBUG("No mechs found for [%s], ignoring.\n", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                safefree(secname);
                continue;
            }
            safefree(secname);
        }
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
        return ret;
    }

    *ctxp = ctx;

    return 0;
}

int load_config(struct gp_config *cfg)
{
    struct gp_ini_context *ctx;
    char *tmpstr;
    int ret;

    ret = gp_init_ini_context(cfg->config_file, &ctx);
    if (ret) {
        return ret;
    }

    tmpstr = gp_config_get_string(ctx, "gssproxy", "debug");
    if (tmpstr) {
        if (option_is_set(tmpstr)) {
            gp_debug_enable();
        }
    }

    cfg->num_workers = gp_config_get_int(ctx, "gssproxy", "worker threads");

    ret = load_services(cfg, ctx);

    gp_config_close(ctx);
    return ret;
}

struct gp_config *read_config(char *config_file, int opt_daemonize)
{
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

    cfg->socket_name = strdup(GP_SOCKET_NAME);
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
        GPDEBUG("Config file not found! Proceeding with defaults.\n");
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

    for (i=0; i < config->num_svcs; i++) {
        gp_service_free(config->svcs[i]);
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

char *gp_config_get_string(struct gp_ini_context *ctx,
                           const char *secname,
                           const char *keyname)
{
    return gp_iniparser_get_string(ctx, secname, keyname);
}

char **gp_config_get_string_array(struct gp_ini_context *ctx,
                                  const char *secname,
                                  const char *keyname,
                                  int *num_values)
{
    return NULL;
}

int gp_config_get_int(struct gp_ini_context *ctx,
                      const char *secname,
                      const char *keyname)
{
    return gp_iniparser_get_int(ctx, secname, keyname);
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

char *gp_config_get_string(struct gp_ini_context *ctx,
                           const char *secname,
                           const char *keyname)
{
    return gp_dinglibs_get_string(ctx, secname, keyname);
}

char **gp_config_get_string_array(struct gp_ini_context *ctx,
                                  const char *secname,
                                  const char *keyname,
                                  int *num_values)
{
    return gp_dinglibs_get_string_array(ctx, secname, keyname, num_values);
}

int gp_config_get_int(struct gp_ini_context *ctx,
                     const char *secname,
                      const char *keyname)
{
    return gp_dinglibs_get_int(ctx, secname, keyname);
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
