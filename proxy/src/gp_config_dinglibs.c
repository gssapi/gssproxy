/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>
   Copyright (C) 2012-2013 Guenther Deschner <guenther.deschner@redhat.com>

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
#include "gp_config_dinglibs.h"

#ifdef WITH_DINGLIBS

#include <ini_configobj.h>

int gp_dinglibs_get_string(struct gp_ini_context *ctx,
                           const char *secname,
                           const char *key,
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
                                  key,
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

int gp_dinglibs_get_string_array(struct gp_ini_context *ctx,
                                 const char *secname,
                                 const char *key,
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
                                  key,
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
                                      key,
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

int gp_dinglibs_get_int(struct gp_ini_context *ctx,
                        const char *secname,
                        const char *key,
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
                                  key,
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

int gp_dinglibs_init(const char *config_file,
                     struct gp_ini_context *ctx)
{
    struct ini_cfgobj *ini_config = NULL;
    struct ini_cfgfile *file_ctx = NULL;
    int ret;

    if (!ctx) {
        return EINVAL;
    }

    ret = ini_config_create(&ini_config);
    if (ret) {
        return ENOENT;
    }

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
                           /* Merge section but allow duplicates */
                           INI_MS_MERGE |
                           INI_MV1S_ALLOW |
                           INI_MV2S_ALLOW,
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

    ctx->private_data = ini_config;

    return 0;
}

int gp_dinglibs_close(struct gp_ini_context *ctx)
{
    struct ini_cfgobj *ini_config = NULL;

    if (!ctx) {
        return 0;
    }

    ini_config = (struct ini_cfgobj *)ctx->private_data;

    ini_config_destroy(ini_config);

    return 0;
}

int gp_dinglibs_get_nsec(struct gp_ini_context *ctx)
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

char *gp_dinglibs_get_secname(struct gp_ini_context *ctx,
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

#endif /* WITH_DINGLIBS */
