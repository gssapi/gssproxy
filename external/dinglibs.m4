AC_DEFUN([WITH_LIBINI_CONFIG],
[
  PKG_CHECK_MODULES([LIBINI_CONFIG], [ini_config >= 1.2.0],
  [
    INI_CONFIG_CFLAGS="`$PKG_CONFIG --cflags ini_config`"
    INI_CONFIG_LIBS="`$PKG_CONFIG --libs ini_config`"
    AC_CHECK_LIB(ini_config, ini_config_file_open, [],
                 [AC_MSG_ERROR([ini_config library must support ini_config_file_open])],
                 [$INI_CONFIG_LIBS])
    AC_CHECK_LIB(ini_config, ini_config_augment, [],
                 [AC_MSG_ERROR([ini_config library must support ini_config_augment])],
                 [$INI_CONFIG_LIBS])
    have_libini_config=yes
  ], [
    AC_MSG_ERROR([Could not find LIBINI_CONFIG headers])
    have_libini_config=no
  ])
])

AC_DEFUN([WITH_REF_ARRAY], [

AC_CHECK_LIB(ref_array, ref_array_destroy, [],
             [AC_MSG_ERROR([library must support ref_array_destroy])],
             [$INI_CONFIG_LIBS])

AC_RUN_IFELSE([AC_LANG_SOURCE([[
/* See: https://pagure.io/SSSD/ding-libs/pull-request/3172 */
#include <linux/limits.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ini_configobj.h>
#include <ini_config.h>

static int write_to_file(char *path, char *text)
{
    FILE *f = fopen(path, "w");
    int bytes = 0;
    if (f == NULL)
        return 1;

    bytes = fprintf(f, "%s", text);
    if (bytes < 0 || (size_t)bytes != strlen(text))
        return 1;

    return fclose(f);
}

int main(void)
{
    char base_path[PATH_MAX];
    char augment_path[PATH_MAX];

    char config_base[] =
        "[section]\n"
        "key1 = first\n"
        "key2 = exists\n";

    char config_augment[] =
        "[section]\n"
        "key1 = augment\n"
        "key3 = exists\n";

    char *builddir;

    struct ini_cfgobj *in_cfg, *result_cfg;
    struct ini_cfgfile *file_ctx;

    uint32_t merge_flags = INI_MS_DETECT | INI_MS_PRESERVE;

    int ret;

    builddir = getenv("builddir");
    if (builddir == NULL) {
        builddir = strdup(".");
    }

    snprintf(base_path, PATH_MAX, "%s/tmp_augment_base.conf", builddir);
    snprintf(augment_path, PATH_MAX, "%s/tmp_augment_augment.conf", builddir);

    ret = write_to_file(base_path, config_base);
    if (ret != 0) {
        ret = 1;
        goto cleanup;
    }

    ret = write_to_file(augment_path, config_augment);
    if (ret != 0) {
        goto cleanup;
    }

    /* Match only augment.conf */
    const char *m_patterns[] = { "^tmp_augment_augment.conf$", NULL };

     /* Match all sections */
    const char *m_sections[] = { ".*", NULL };

    /* Create config collection */
    ret = ini_config_create(&in_cfg);
    if (ret != EOK)
        goto cleanup;

    /* Open base.conf */
    ret = ini_config_file_open(base_path, 0, &file_ctx);
    if (ret != EOK)
        goto cleanup;

    /* Seed in_cfg with base.conf */
    ret = ini_config_parse(file_ctx, 1, 0, 0, in_cfg);
    if (ret != EOK)
        goto cleanup;

    /* Update base.conf with augment.conf */
    ret = ini_config_augment(in_cfg,
                             builddir,
                             m_patterns,
                             m_sections,
                             NULL,
                             INI_STOP_ON_NONE,
                             0,
                             INI_PARSE_NOSPACE|INI_PARSE_NOTAB,
                             merge_flags,
                             &result_cfg,
                             NULL,
                             NULL);
    /* We always expect EEXIST due to DETECT being set. */
    if (ret != EEXIST)
        goto cleanup;

    ret = 0;

cleanup:
    remove(base_path);
    remove(augment_path);

    /* Per autoconf guidelines */
    if (ret != 0)
        ret = 1;

    return ret;
}
]])]
,, [AC_MSG_ERROR(["ini_config library must support extended INI_MS_DETECT."])], AC_MSG_WARN(["Cross Compiling. Make sure your ini_config library supports extended INI_MS_DETECT"]))

])
