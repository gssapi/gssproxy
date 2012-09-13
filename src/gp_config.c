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
#include "iniparser.h"

#define GP_SOCKET_NAME "gssproxy.socket"

static void gp_service_free(struct gp_service *svc)
{
    free(svc->name);
    if (svc->mechs & GP_CRED_KRB5) {
        free(svc->krb5.principal);
        free(svc->krb5.keytab);
        free(svc->krb5.ccache);
    }
    gp_free_creds_handle(&svc->creds_handle);
    memset(svc, 0, sizeof(struct gp_service));
}

static char *get_char_value(dictionary *dict,
                            const char *secname,
                            const char *key)
{
    char *skey;
    char *value;
    int ret;

    ret = asprintf(&skey, "%s:%s", secname, key);
    if (ret == -1) {
        return NULL;
    }

    value = iniparser_getstring(dict, skey, NULL);
    free(skey);
    return value;
}

static int get_int_value(dictionary *dict,
                         const char *secname,
                         const char *key)
{
    char *skey;
    int ret;

    ret = asprintf(&skey, "%s:%s", secname, key);
    if (ret == -1) {
        return -1;
    }

    ret = iniparser_getint(dict, skey, -1);
    free(skey);
    return ret;
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
                             dictionary *dict,
                             const char *secname)
{
    const char *value;

    value = get_char_value(dict, secname, "krb5_principal");
    if (value) {
        svc->krb5.principal = strdup(value);
        if (!svc->krb5.principal) {
            return ENOMEM;
        }
    }

    value = get_char_value(dict, secname, "krb5_keytab");
    if (value) {
        svc->krb5.keytab = strdup(value);
        if (!svc->krb5.keytab) {
            return ENOMEM;
        }
    }

    value = get_char_value(dict, secname, "krb5_ccache");
    if (value) {
        svc->krb5.ccache = strdup(value);
        if (!svc->krb5.ccache) {
            return ENOMEM;
        }
    }

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

static int load_services(struct gp_config *cfg, dictionary *dict)
{
    int num_sec;
    char *secname;
    char *value;
    char *token;
    char *handle;
    int valnum;
    int ret;
    int i, n;

    num_sec = iniparser_getnsec(dict);

    /* allocate enough space for num_sec services,
     * we won't waste too much space by overallocating */
    cfg->svcs = calloc(num_sec, sizeof(struct gp_service *));
    if (!cfg->svcs) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_sec; i++) {
        secname = iniparser_getsecname(dict, i);

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

            valnum = get_int_value(dict, secname, "euid");
            if (valnum == -1) {
                /* malformed section, mech is missing */
                GPDEBUG("Euid missing from [%s], ignoring.", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                continue;
            }
            cfg->svcs[n]->euid = valnum;

            value = get_char_value(dict, secname, "trusted");
            if (value != NULL) {
                if (option_is_set(value)) {
                    cfg->svcs[n]->trusted = true;
                }
            }

            ret = setup_service_creds_handle(cfg->svcs[n]);
            if (ret) {
                goto done;
            }

            value = get_char_value(dict, secname, "mechs");
            if (value == NULL) {
                /* malformed section, mech is missing */
                GPDEBUG("Mechs missing from [%s], ignoring.", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                continue;
            }

            token = strtok_r(value, ", ", &handle);
            do {

                ret = strcmp(value, "krb5");
                if (ret == 0) {
                    ret = get_krb5_mech_cfg(cfg->svcs[n], dict, secname);
                    if (ret == 0) {
                        cfg->svcs[n]->mechs |= GP_CRED_KRB5;
                    } else {
                        GPDEBUG("Failed to read krb5 config for %s, ignoring.",
                                secname);
                    }
                } else {
                    GPDEBUG("Unknown mech: %s in [%s], ignoring.",
                            token, secname);
                }

                token = strtok_r(NULL, ", ", &handle);
            } while (token != NULL);

            if (cfg->svcs[n]->mechs == 0) {
                GPDEBUG("No mechs found for [%s], ignoring.", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                continue;
            }
        }
    }

    if (cfg->num_svcs == 0) {
        GPERROR("No service sections configured!");
        return ENOENT;
    }

    ret = 0;

done:
    return ret;
}

int load_config(struct gp_config *cfg)
{
    dictionary *d;
    char *tmpstr;
    int ret;
    uint32_t ret_min, ret_maj;

    d = iniparser_load(cfg->config_file);
    if (!d) {
        return ENOENT;
    }

    tmpstr = iniparser_getstring(d, "gssproxy:debug", NULL);
    if (tmpstr) {
        if (option_is_set(tmpstr)) {
            gp_debug_enable();
        }
    }

    tmpstr = iniparser_getstring(d, "gssproxy:socket", NULL);
    if (tmpstr) {
        cfg->socket_name = strdup(tmpstr);
        if (!cfg->socket_name) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = asprintf(&cfg->socket_name, "%s/%s",
                        PIPE_PATH, GP_SOCKET_NAME);
        if (ret == -1) {
            ret = ENOMEM;
            goto done;
        }
    }

    cfg->num_workers = iniparser_getint(d, "gssproxy:worker threads", 0);

    ret = load_services(cfg, d);

done:
    iniparser_freedict(d);
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
        GPDEBUG("Config file not found! Proceeding with defaults.");
    }

    return cfg;
}

struct gp_creds_handle *gp_service_get_creds_handle(struct gp_service *svc)
{
    return svc->creds_handle;
}

void free_config(struct gp_config *config)
{
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
}
