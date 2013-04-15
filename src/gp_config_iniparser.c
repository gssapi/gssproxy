/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>
   Copyright (C) 2012 Guenther Deschner <guenther.deschner@redhat.com>

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
#include "gp_config_iniparser.h"

#ifdef WITH_INIPARSER

#include <iniparser.h>

int gp_iniparser_get_string(struct gp_ini_context *ctx,
                            const char *secname,
                            const char *key,
                            char **value)
{
    dictionary *dict;
    char *skey;
    char *val;
    int ret;

    dict = (dictionary *)ctx->private_data;

    if (!value) {
        return EINVAL;
    }

    *value = NULL;

    ret = asprintf(&skey, "%s:%s", secname, key);
    if (ret == -1) {
        return ENOMEM;
    }

    val = iniparser_getstring(dict, skey, NULL);
    free(skey);

    if (!val) {
        return ENOENT;
    }

    *value = val;

    return 0;
}

int gp_iniparser_get_int(struct gp_ini_context *ctx,
                         const char *secname,
                         const char *key,
                         int *value)
{
    dictionary *dict;
    char *skey;
    int ret;

    dict = (dictionary *)ctx->private_data;

    if (!value) {
        return EINVAL;
    }

    *value = -1;

    ret = asprintf(&skey, "%s:%s", secname, key);
    if (ret == -1) {
        return ENOMEM;
    }

    ret = iniparser_getint(dict, skey, -1);
    free(skey);

    if (ret == -1) {
        return ENOENT;
    }

    *value = ret;

    return 0;
}

int gp_iniparser_init(const char *config_file,
                      struct gp_ini_context *ctx)
{
    dictionary *d;

    if (!ctx) {
        return EINVAL;
    }

    d = iniparser_load(config_file);
    if (!d) {
        return ENOENT;
    }

    ctx->private_data = d;

    return 0;
}

int gp_iniparser_close(struct gp_ini_context *ctx)
{
    dictionary *dict;

    if (!ctx) {
        return 0;
    }

    dict = (dictionary *)ctx->private_data;

    iniparser_freedict(dict);

    return 0;
}

int gp_iniparser_get_nsec(struct gp_ini_context *ctx)
{
    dictionary *dict = dict = (dictionary *)ctx->private_data;

    return iniparser_getnsec(dict);
}

char *gp_iniparser_get_secname(struct gp_ini_context *ctx,
                                      int i)
{
    dictionary *dict = dict = (dictionary *)ctx->private_data;
    char *value;

    value = iniparser_getsecname(dict, i);
    if (!value) {
        return NULL;
    }

    return strdup(value);
}

#endif /* WITH_INIPARSER */
