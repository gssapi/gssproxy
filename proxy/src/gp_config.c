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
#include <syslog.h>
#include <errno.h>
#include "gp_proxy.h"
#include "iniparser.h"

#define GP_SOCKET_NAME "gssproxy.socket"

static void gp_credcfg_free(struct gp_credcfg *cred)
{
    free(cred->name);
    if (cred->mech == GP_CRED_KRB5) {
        free(cred->cred.krb5.keytab);
        free(cred->cred.krb5.ccache);
    }
    memset(cred, 0, sizeof(struct gp_credcfg));
}

static void gp_service_free(struct gp_service *svc)
{
    free(svc->name);
    free(svc->creds);
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

static int get_krb5_mech_cfg(struct gp_credcfg *cred,
                             dictionary *dict,
                             const char *secname)
{
    const char *value;

    cred->name = strdup(&secname[11]); /* name after 'credentials/' */
    if (!cred->name) {
        return ENOMEM;
    }

    cred->mech = GP_CRED_KRB5;

    value = get_char_value(dict, secname, "krb5_keytab");
    if (value) {
        cred->cred.krb5.keytab = strdup(value);
        if (!cred->cred.krb5.keytab) {
            return ENOMEM;
        }
    }

    value = get_char_value(dict, secname, "krb5_ccache");
    if (value) {
        cred->cred.krb5.ccache = strdup(value);
        if (!cred->cred.krb5.ccache) {
            return ENOMEM;
        }
    }

    return 0;
}

static int get_creds_config(char *name, dictionary *dict,
                            struct gp_service *svc,
                            struct gp_credcfg **creds, int num_creds)
{
    char *value;
    char *token;
    char *handle;
    int i, n;

    svc->name = strdup(&name[8]); /* name after 'service/' */
    if (!svc->name) {
        return ENOMEM;
    }

    svc->creds = calloc(num_creds, sizeof(struct gp_credcfg *));
    if (!svc->creds) {
        return ENOMEM;
    }

    value = get_char_value(dict, name, "credentials");
    if (value == NULL) {
        /* malformed section, crentials is missing */
        syslog(LOG_INFO,
               "Credentials missing from [%s], ignoring.", name);
        return EINVAL;
    }

    n = 0;
    token = strtok_r(value, ", ", &handle);
    do {
        for (i = 0; i < num_creds; i++) {
            if (strcmp(token, creds[i]->name) == 0) {
                svc->creds[n] = creds[i];
                n++;
                break;
            }
        }

        token = strtok_r(NULL, ", ", &handle);
    } while (token != NULL);

    svc->num_creds = n;

    return 0;
}

static int load_services(struct gp_config *cfg, dictionary *dict)
{
    int num_sec;
    char *secname;
    char *value;
    int valnum;
    int ret;
    int i, n;

    num_sec = iniparser_getnsec(dict);

    /* allocate enough space for num_sec services and creds, will trim it
     * later when we know what is what */
    cfg->creds = calloc(num_sec, sizeof(struct gp_credcfg *));
    if (!cfg->creds) {
        ret = ENOMEM;
        goto done;
    }
    cfg->svcs = calloc(num_sec, sizeof(struct gp_service *));
    if (!cfg->svcs) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_sec; i++) {
        secname = iniparser_getsecname(dict, i);
        ret = strncmp(secname, "credential/", 10);
        if (ret == 0) {
            n = cfg->num_creds;
            cfg->creds[n] = calloc(1, sizeof(struct gp_credcfg));
            if (!cfg->creds[n]) {
                ret = ENOMEM;
                goto done;
            }
            cfg->num_creds++;

            value = get_char_value(dict, secname, "mech");
            if (value == NULL) {
                /* malformed section, mech is missing */
                syslog(LOG_INFO,
                       "Mech missing from [%s], ignoring.", secname);
                gp_credcfg_free(cfg->creds[n]);
                cfg->num_creds--;
                continue;
            }

            ret = strcmp(value, "krb5");
            if (ret == 0) {
                ret = get_krb5_mech_cfg(cfg->creds[n], dict, secname);
                if (ret != 0) {
                    gp_credcfg_free(cfg->creds[n]);
                    cfg->num_creds--;
                    continue;
                }
            } else {
                syslog(LOG_INFO,
                       "Unknown mech: %s in [%s], ignoring.",
                       value, secname);
                gp_credcfg_free(cfg->creds[n]);
                cfg->num_creds--;
                continue;
            }
        }

        ret = strncmp(secname, "service/", 8);
        if (ret == 0) {
            n = cfg->num_svcs;
            cfg->svcs[n] = calloc(1, sizeof(struct gp_service));
            if (!cfg->svcs[n]) {
                ret = ENOMEM;
                goto done;
            }
            cfg->num_svcs++;

            valnum = get_int_value(dict, secname, "euid");
            if (valnum == -1) {
                /* malformed section, mech is missing */
                syslog(LOG_INFO,
                       "Euid missing from [%s], ignoring.", secname);
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                continue;
            }
            cfg->svcs[n]->euid = valnum;

            ret = get_creds_config(secname, dict, cfg->svcs[n],
                                   cfg->creds, cfg->num_creds);
            if (ret) {
                gp_service_free(cfg->svcs[n]);
                cfg->num_svcs--;
                continue;
            }
        }
    }

    if (cfg->num_creds == 0){
        syslog(LOG_ERR, "No credentials sections configured!");
        return ENOENT;
    }

    if (cfg->num_svcs == 0) {
        syslog(LOG_ERR, "No service sections configured!");
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

    d = iniparser_load(cfg->config_file);
    if (!d) {
        return ENOENT;
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
        syslog(LOG_INFO, "Config file not found! Proceeding with defaults.");
    }

    return cfg;
}

