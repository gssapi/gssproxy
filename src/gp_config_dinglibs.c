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

char *gp_dinglibs_get_string(struct gp_ini_context *ctx,
                             const char *secname,
                             const char *key)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    struct value_obj *vo = NULL;
    const char *value;
    int ret;

    ret = ini_get_config_valueobj(secname,
                                  key,
                                  ini_config,
                                  INI_GET_FIRST_VALUE,
                                  &vo);
    if (ret || !vo) {
        return NULL;
    }

    value = ini_get_const_string_config_value(vo, &ret);
    if (ret) {
        return NULL;
    }

    return value;
}

int gp_dinglibs_get_int(struct gp_ini_context *ctx,
                        const char *secname,
                        const char *key)
{
    struct ini_cfgobj *ini_config = (struct ini_cfgobj *)ctx->private_data;
    struct value_obj *vo = NULL;
    int value;
    int ret;

    ret = ini_get_config_valueobj(secname,
                                  key,
                                  ini_config,
                                  INI_GET_FIRST_VALUE,
                                  &vo);

    if (ret || !vo) {
        return -1;
    }

    value = ini_get_int_config_value(vo,
                                     0, /* strict */
                                     0, /* default */
                                     &ret);
    if (ret) {
        return -1;
    }

    return value;
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
            ret, strerror(ret));
        ini_config_destroy(ini_config);
        return ret;
    }

    ret = ini_config_parse(file_ctx,
                           INI_STOP_ON_NONE, /* error_level */
                           /* Merge section but allow duplicates */
                           INI_MS_MERGE |
                           INI_MV1S_ALLOW |
                           INI_MV2S_ALLOW,
                           INI_PARSE_NOWRAP, /* parse_flags */
                           ini_config);
    if (ret) {
        /* we had a parsing failure */
        GPDEBUG("Failed to parse config file: %d (%s)\n",
            ret, strerror(ret));
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
