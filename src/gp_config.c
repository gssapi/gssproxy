/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include "gp_proxy.h"
#include "gp_config.h"
#include "gp_selinux.h"

#include <gssapi/gssapi.h>

#include <ini_configobj.h>

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

void free_cred_store_elements(gss_key_value_set_desc *cs)
{
    if (!cs->elements) return;

    for (unsigned i = 0; i < cs->count; i++) {
        safefree(cs->elements[i].key);
        safefree(cs->elements[i].value);
    }
    safefree(cs->elements);
    cs->count = 0;
}

static void gp_service_free(struct gp_service *svc)
{
    free(svc->name);
    if (svc->mechs & GP_CRED_KRB5) {
        free(svc->krb5.principal);
        free_cred_store_elements(&svc->krb5.store);
        gp_free_creds_handle(&svc->krb5.creds_handle);
    }
    SELINUX_context_free(svc->selinux_ctx);
    memset(svc, 0, sizeof(struct gp_service));
}

static int setup_krb5_creds_handle(struct gp_service *svc)
{
    uint32_t ret_maj, ret_min;
    const char *keytab = NULL;

    for (unsigned i = 0; i < svc->krb5.store.count; i++) {
        if (strcmp(svc->krb5.store.elements[i].key, "keytab") == 0) {
            keytab = svc->krb5.store.elements[i].value;
            break;
        }
    }

    ret_maj = gp_init_creds_handle(&ret_min, svc->name, keytab,
                                   &svc->krb5.creds_handle);
    if (ret_maj) {
        return ret_min;
    }

    return 0;
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
    const char **strings = NULL;
    int count = 0;
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
    ret = gp_config_get_string_array(ctx, secname, "cred_store",
                                     &count, &strings);
    if (ret == 0) {
        const char *p;
        ssize_t len;
        char *key;

        svc->krb5.store.elements =
            calloc(count, sizeof(gss_key_value_element_desc));
        if (!svc->krb5.store.elements) {
            ret = ENOMEM;
            goto done;
        }
        svc->krb5.store.count = count;

        for (int c = 0; c < count; c++) {
            p = strchr(strings[c], ':');
            if (!p) {
                GPERROR("Invalid cred_store value, no ':' separator found in"
                        " [%s].\n", strings[c]);
                ret = EINVAL;
                goto done;
            }
            len = asprintf(&key, "%.*s", (int)(p - strings[c]), strings[c]);
            if (len == -1) {
                ret = ENOMEM;
                goto done;
            }
            svc->krb5.store.elements[c].key = key;
            svc->krb5.store.elements[c].value = strdup(p + 1);
            if (!svc->krb5.store.elements[c].value) {
                ret = ENOMEM;
                goto done;
            }
        }

    } else if (ret == ENOENT) {
        /* when not there we ignore */
        ret = 0;
    }

    if (ret == 0) {
        ret = setup_krb5_creds_handle(svc);
    }

done:
    free_str_array(&strings, &count);
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

static int check_services(const struct gp_config *cfg)
{
    int i, j;
    struct gp_service *isvc, *jsvc;
    const char *isock, *jsock;
    int ret = 0;

    /* [gssproxy] section does not get placed in svcs */
    for (i = 0; i < cfg->num_svcs; i++) {
        isvc = cfg->svcs[i];
        isock = isvc->socket;
        if (!isock) {
            isock = GP_SOCKET_NAME;
        }

        for (j = 0; j < i; j++) {
            jsvc = cfg->svcs[j];
            jsock = jsvc->socket;
            if (!jsock) {
                jsock = GP_SOCKET_NAME;
            }

            if (!gp_same(isock, jsock) ||
                !gp_selinux_ctx_equal(isvc->selinux_ctx, jsvc->selinux_ctx)) {
                continue;
            }

            if (jsvc->any_uid) {
                ret = 1;
                GPERROR("%s sets allow_any_uid with the same socket and "
                        "selinux_context as %s!\n", jsvc->name, isvc->name);
            } else if (jsvc->euid == isvc->euid) {
                ret = 1;
                GPERROR("socket, selinux_context, and euid for %s and %s "
                        "should not match!\n", isvc->name, jsvc->name);
            }
        }
    }

    return ret;
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

            /* euid can be a string or an int */
            ret = gp_config_get_int(ctx, secname, "euid", &valnum);
            if (ret != 0) {
                ret = gp_config_get_string(ctx, secname, "euid", &value);
                if (ret == 0) {
                    struct passwd *eu_passwd; /* static; do not free */

                    errno = 0; /* needs to be 0; otherwise it won't be set */
                    eu_passwd = getpwnam(value);
                    if (!eu_passwd) {
                        ret = errno;
                        if (ret == 0) { /* not that it gets set anyway... */
                            ret = ENOENT;
                        }
                    } else {
                        valnum = eu_passwd->pw_uid;
                    }
                }
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
            }
            cfg->svcs[n]->euid = valnum;

            ret = gp_config_get_string(ctx, secname, "allow_any_uid", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->any_uid = true;
                }
            }

            ret = gp_config_get_string(ctx, secname,
                                       "allow_protocol_transition", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->allow_proto_trans = true;
                }
            }

            ret = gp_config_get_string(ctx, secname,
                                       "allow_constrained_delegation", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->allow_const_deleg = true;
                }
            }

            ret = gp_config_get_string(ctx, secname,
                                       "allow_client_ccache_sync", &value);
            if (ret == 0) {
                if (gp_boolean_is_true(value)) {
                    cfg->svcs[n]->allow_cc_sync = true;
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
                GPDEBUG(
                    "selinux_ctx is deprecated; use euid/socket instead.\n");
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

    ret = check_services(cfg);

done:
    safefree(secname);
    return ret;
}

static int gp_init_ini_context(const char *config_file,
                               const char *config_dir,
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

    ret = gp_config_init(config_file, config_dir, ctx);

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
    int tmp_dbg_lvl = 0;
    int tmpint = 0;
    int ret;

    ret = gp_init_ini_context(cfg->config_file, cfg->config_dir, &ctx);
    if (ret) {
        return ret;
    }

    ret = gp_config_get_string(ctx, "gssproxy", "debug", &tmpstr);
    if (ret == 0) {
        if (gp_boolean_is_true(tmpstr)) {
            if (tmp_dbg_lvl == 0) {
                tmp_dbg_lvl = 1;
            }
        }
    } else if (ret != ENOENT) {
        goto done;
    }

    ret = gp_config_get_int(ctx, "gssproxy", "debug_level", &tmpint);
    if (ret == 0) {
        tmp_dbg_lvl = tmpint;
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
    gp_debug_toggle(tmp_dbg_lvl);
    gp_config_close(ctx);
    safefree(ctx);
    return ret;
}

struct gp_config *read_config(char *config_file, char *config_dir,
                              char *socket_name, int opt_daemonize)
{
    const char *socket = GP_SOCKET_NAME;
    const char *dir = NULL;
    struct gp_config *cfg;
    int ret;

    cfg = calloc(1, sizeof(struct gp_config));
    if (!cfg) {
        return NULL;
    }

    if (config_file) {
        cfg->config_file = strdup(config_file);
        if (!cfg->config_file) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        ret = asprintf(&cfg->config_file, "%s/gssproxy.conf", PUBCONF_PATH);
        if (ret == -1) {
            goto done;
        }
    }

    if (config_dir) {
        dir = config_dir;
    } else if (!config_file) {
        dir = PUBCONF_PATH;
    }

    if (dir) {
        cfg->config_dir = strdup(dir);
        if (!cfg->config_dir) {
            ret = ENOMEM;
            goto done;
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
        GPDEBUG("Config file(s) not found!\n");
    }

done:
    if (ret) {
        /* recursively frees cfg */
        free_config(&cfg);
        return NULL;
    }

    return cfg;
}

struct gp_creds_handle *gp_service_get_creds_handle(struct gp_service *svc)
{
    return svc->krb5.creds_handle;
}

void free_config(struct gp_config **cfg)
{
    struct gp_config *config = *cfg;

    if (!config) {
        return;
    }

    free(config->config_file);
    free(config->config_dir);
    free(config->socket_name);
    free(config->proxy_user);

    for (int i = 0; i < config->num_svcs; i++) {
        gp_service_free(config->svcs[i]);
        safefree(config->svcs[i]);
    }

    free(config->svcs);
    free(config);
    *cfg = NULL;
}

static int gp_config_from_file(const char *config_file,
                               struct ini_cfgobj *ini_config,
                               const uint32_t collision_flags)
{
    struct ini_cfgfile *file_ctx = NULL;
    int ret;

    ret = ini_config_file_open(config_file,
                               0, /* metadata_flags, FIXME */
                               &file_ctx);
    if (ret) {
        GPDEBUG("Failed to open config file: %d (%s)\n",
                ret, gp_strerror(ret));
        ini_config_destroy(ini_config);
        return ret;
    }

    ret = ini_config_parse(file_ctx,
                           INI_STOP_ON_ANY, /* error_level */
                           collision_flags,
                           INI_PARSE_NOWRAP, /* parse_flags */
                           ini_config);
    if (ret) {
        char **errors = NULL;
        /* we had a parsing failure */
        GPDEBUG("Failed to parse config file: %d (%s)\n",
                ret, gp_strerror(ret));
        if (ini_config_error_count(ini_config)) {
            ini_config_get_errors(ini_config, &errors);
            if (errors) {
                ini_config_print_errors(stderr, errors);
                ini_config_free_errors(errors);
            }
        }
        ini_config_file_destroy(file_ctx);
        ini_config_destroy(ini_config);
        return ret;
    }

    ini_config_file_destroy(file_ctx);
    return 0;
}

static int gp_config_from_dir(const char *config_dir,
                              struct ini_cfgobj **ini_config,
                              const uint32_t collision_flags)
{
    struct ini_cfgobj *result_cfg = NULL;
    struct ref_array *error_list = NULL;
    int ret;

    const char *patterns[] = {
        /* match only files starting with "##-" and ending in ".conf" */
        "^[0-9]\\{2\\}-.\\{1,\\}\\.conf$",
        NULL,
    };

    const char *sections[] = {
        /* match either "gssproxy" or sections that start with "service/" */
        "^gssproxy$",
        "^service/.*$",
        NULL,
    };

    /* Permission check failures silently skip the file, so they are not
     * useful to us. */
    ret = ini_config_augment(*ini_config,
                             config_dir,
                             patterns,
                             sections,
                             NULL, /* check_perm */
                             INI_STOP_ON_ANY, /* error_level */
                             collision_flags,
                             INI_PARSE_NOWRAP,
                             /* do not allow colliding sections with the same
                              * name in different files */
                             INI_MS_ERROR,
                             &result_cfg,
                             &error_list,
                             NULL);
    if (ret) {
        if (error_list) {
            uint32_t i;
            uint32_t len = ref_array_getlen(error_list, &i);
            for (i = 0; i < len; i++) {
                GPDEBUG("Error when reading config directory: %s\n",
                        (const char *) ref_array_get(error_list, i, NULL));
            }
            ref_array_destroy(error_list);
        } else {
            GPDEBUG("Error when reading config directory number: %d\n", ret);
        }
        return ret;
    }

    /* if we read no new files, result_cfg will be NULL */
    if (result_cfg) {
        ini_config_destroy(*ini_config);
        *ini_config = result_cfg;
    }
    if (error_list) {
        ref_array_destroy(error_list);
    }
    return 0;
}

int gp_config_init(const char *config_file, const char *config_dir,
                   struct gp_ini_context *ctx)
{
    struct ini_cfgobj *ini_config = NULL;
    int ret;

    /* Within a single file, merge all collisions */
    const uint32_t collision_flags =
      INI_MS_MERGE | INI_MV1S_ALLOW | INI_MV2S_ALLOW;

    if (!ctx) {
        return EINVAL;
    }

    ret = ini_config_create(&ini_config);
    if (ret) {
        return ENOENT;
    }

    if (config_file) {
        ret = gp_config_from_file(config_file, ini_config, collision_flags);
        if (ret) {
            GPDEBUG("Error when trying to read config file %s.\n",
                    config_file);
            return ret;
        }
    }
    if (config_dir) {
        ret = gp_config_from_dir(config_dir, &ini_config, collision_flags);
        if (ret) {
            GPDEBUG("Error when trying to read config directory %s.\n",
                    config_dir);
            return ret;
        }
    }

    ctx->private_data = ini_config;

    return 0;
}

int gp_config_get_string(struct gp_ini_context *ctx,
                         const char *secname,
                         const char *keyname,
                         const char **value)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    struct value_obj *vo = NULL;
    int ret;
    const char *val;

    if (!value) {
        return -1;
    }

    *value = NULL;

    ret = ini_get_config_valueobj(secname,
                                  keyname,
                                  ini_config,
                                  INI_GET_FIRST_VALUE,
                                  &vo);
    if (ret) {
        return ret;
    }
    if (!vo) {
        return ENOENT;
    }

    val = ini_get_const_string_config_value(vo, &ret);
    if (ret) {
        return ret;
    }

    *value = val;

    return 0;
}

int gp_config_get_string_array(struct gp_ini_context *ctx,
                               const char *secname,
                               const char *keyname,
                               int *num_values,
                               const char ***values)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    struct value_obj *vo = NULL;
    const char *value;
    int ret;
    int i, count = 0;
    const char **array = NULL;
    const char **t_array;

    if (!values || !num_values) {
        return EINVAL;
    }

    *num_values = 0;
    *values = NULL;

    ret = ini_get_config_valueobj(secname,
                                  keyname,
                                  ini_config,
                                  INI_GET_FIRST_VALUE,
                                  &vo);
    if (ret) {
        return ret;
    }
    if (!vo) {
        return ENOENT;
    }

    value = ini_get_const_string_config_value(vo, &ret);
    if (ret) {
        return ret;
    }

    array = calloc(1, sizeof(char *));
    if (array == NULL) {
        ret = ENOMEM;
        goto done;
    }

    array[count] = strdup(value);
    if (array[count] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    count++;

    do {
        ret = ini_get_config_valueobj(secname,
                                      keyname,
                                      ini_config,
                                      INI_GET_NEXT_VALUE,
                                      &vo);
        if (ret) {
            goto done;
        }
        if (!vo) {
            break;
        }

        value = ini_get_const_string_config_value(vo, &ret);
        if (ret) {
            goto done;
        }

        t_array = realloc(array, (count+1) * sizeof(char *));
        if (t_array == NULL) {
            ret = ENOMEM;
            goto done;
        }
        array = t_array;

        array[count] = strdup(value);
        if (array[count] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        count++;

    } while (1);

    *num_values = count;
    *values = array;

    ret = 0;

done:
    if (ret && array) {
        for (i = 0; i < count; i++) {
            safefree(array[i]);
        }
        safefree(array);
    }
    return ret;
}

int gp_config_get_int(struct gp_ini_context *ctx,
                      const char *secname,
                      const char *keyname,
                      int *value)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    struct value_obj *vo = NULL;
    int ret;
    int val;

    if (!value) {
        return EINVAL;
    }

    *value = -1;

    ret = ini_get_config_valueobj(secname,
                                  keyname,
                                  ini_config,
                                  INI_GET_FIRST_VALUE,
                                  &vo);

    if (ret) {
        return ret;
    }
    if (!vo) {
        return ENOENT;
    }

    val = ini_get_int_config_value(vo,
                                   0, /* strict */
                                   0, /* default */
                                   &ret);
    if (ret) {
        return ret;
    }

    *value = val;

    return 0;
}

int gp_config_get_nsec(struct gp_ini_context *ctx)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    char **list = NULL;
    int count;
    int error;

    list = ini_get_section_list(ini_config, &count, &error);
    if (error) {
        return 0;
    }

    ini_free_section_list(list);

    return count;
}

char *gp_config_get_secname(struct gp_ini_context *ctx,
                            int i)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    char **list = NULL;
    int count;
    int error;
    char *secname;

    list = ini_get_section_list(ini_config, &count, &error);
    if (error) {
        return NULL;
    }

    if (i >= count) {
        return NULL;
    }

    secname = strdup(list[i]);
    ini_free_section_list(list);
    if (!secname) {
        return NULL;
    }

    return secname;
}

int gp_config_close(struct gp_ini_context *ctx)
{
    struct ini_cfgobj *ini_config = NULL;

    if (!ctx) {
        return 0;
    }

    ini_config = (struct ini_cfgobj *)ctx->private_data;

    ini_config_destroy(ini_config);

    return 0;
}
