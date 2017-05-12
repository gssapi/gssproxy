AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([gssproxy],
        VERSION_NUMBER,
        [simo@redhat.com])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

AC_PROG_CC_C99
CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AC_CONFIG_SRCDIR([BUILD.txt])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax])
AM_PROG_CC_C_O
AM_PROG_AR
AC_PROG_INSTALL
LT_INIT([disable-static])
AC_CONFIG_MACRO_DIR([m4])
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.14])

AC_SUBST([PRERELEASE_VERSION],
         PRERELEASE_VERSION_NUMBER)

AC_DEFINE([PRERELEASE_VERSION], "PRERELEASE_VERSION_NUMBER",
          [Prerelease version number of package])

AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 &>/dev/null])

m4_pattern_allow([AM_SILENT_RULES])
AM_SILENT_RULES

AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])

AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)

AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

m4_include([build_macros.m4])
BUILD_WITH_SHARED_BUILD_DIR

AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[#include <pthread.h>]],
        [[pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;]])],
    [AC_DEFINE([HAVE_PTHREAD], [1], [Pthread mutexes available.])],
    [AC_MSG_WARN([Pthread library not found! Clients will not be thread safe...])])

m4_include([external/platform.m4])

m4_include(conf_macros.m4)
WITH_DISTRO_VERSION
WITH_CC_PATH
WITH_LOG_PATH
WITH_PUBCONF_PATH
WITH_SOCKET_NAME
WITH_PID_FILE
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG
WITH_SELINUX
WITH_GSSIDEBUG
WITH_GPSTATE_PATH
WITH_GPP_DEFAULT_BEHAVIOR
WITH_HARDENING

m4_include([external/pkg.m4])
m4_include([external/libpopt.m4])
m4_include([external/docbook.m4])
m4_include([external/sizes.m4])
m4_include([external/selinux.m4])
m4_include([external/libkeyutils.m4])
m4_include([external/systemd.m4])
m4_include([external/ax_pthread.m4])

PKG_CHECK_MODULES([VERTO], [libverto >= 0.2.2], [have_libverto=1], [have_libverto=])
if test x$have_libverto = x; then
    AC_MSG_ERROR([Could not find VERTO headers])
fi

#Check for libini_config
PKG_CHECK_MODULES([LIBINI_CONFIG], [ini_config >= 1.2.0], [have_libini_config=1], [have_libini_config=])
if test x$have_libini_config = x; then
    AC_MSG_WARN([Could not find LIBINI_CONFIG headers])
else
    INI_CONFIG_CFLAGS="`$PKG_CONFIG --cflags ini_config`"
    INI_CONFIG_LIBS="`$PKG_CONFIG --libs ini_config`"
    AC_CHECK_LIB(ini_config, ini_config_file_open, [],
                 [AC_MSG_WARN([ini_config library must support ini_config_file_open])],
                 [$INI_CONFIG_LIBS])
    AC_CHECK_LIB(ini_config, ini_config_augment, [],
                 [AC_MSG_WARN([ini_config library must support ini_config_augment])],
                 [$INI_CONFIG_LIBS])
fi

if test x$have_libini_config = x1; then
    INI_CFLAGS="$INI_CONFIG_CFLAGS"
    INI_LIBS="$INI_CONFIG_LIBS"
else
    AC_MSG_ERROR([ini_config development packages not available])
fi

AC_SUBST(INI_LIBS)
AC_SUBST(INI_CFLAGS)

AX_PTHREAD(,[AC_MSG_ERROR([Could not find Pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS"
LIBS="$PTHREAD_CFLAGS $CFLAGS"
CC="$PTHREAD_CC"

AC_CHECK_HEADERS([gssapi/gssapi.h],,[AC_MSG_ERROR([Could not find GSSAPI headers])])
PKG_CHECK_MODULES([KRB5_GSSAPI], [krb5-gssapi >= 1.12.0],
                  [have_krb5_gssapi=1], [have_krb5_gssapi=])
if test x$have_krb5_gssapi = x; then
    AC_MSG_ERROR([Could not find Krb5 / GSSAPI development libraries])
else
    KRB5_CFLAGS="`$PKG_CONFIG --cflags krb5`"
    KRB5_LIBS="`$PKG_CONFIG --libs krb5`"
    GSSAPI_CFLAGS="`$PKG_CONFIG --cflags krb5-gssapi`"
    GSSAPI_LIBS="`$PKG_CONFIG --libs krb5-gssapi`"
fi
AC_CHECK_LIB(gssapi_krb5, gss_import_cred,,
             [AC_MSG_ERROR([GSSAPI library does not support gss_import_cred])],
             [$GSSAPI_LIBS])
AC_CHECK_LIB(gssapi_krb5, gss_export_cred,,
             [AC_MSG_ERROR([GSSAPI library does not support gss_export_cred])],
             [$GSSAPI_LIBS])

AC_CHECK_DECLS([GSS_KRB5_GET_CRED_IMPERSONATOR], [], [],
               [[#include <gssapi/gssapi_krb5.h>]])
AC_CHECK_DECLS([GSS_KRB5_CRED_NO_CI_FLAGS_X], [],
               [AC_MSG_ERROR([krb5 too old; missing GSS_KRB5_CRED_NO_CI_FLAGS_X (v1.14)])],
               [[#include <gssapi/gssapi_krb5.h>]])

AC_SUBST([KRB5_CFLAGS])
AC_SUBST([KRB5_LIBS])
AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

AC_CHECK_HEADERS([gssrpc/rpc.h],,[AC_MSG_ERROR([Could not find GSSRPC headers])])
GSSRPC_LIBS="-lgssrpc"
AC_CHECK_LIB(gssrpc, gssrpc_xdrmem_create,,
             [AC_MSG_ERROR([Failed to find GSSRPC symbols])],
             [$GSSAPI_LIBS $GSSRPC_LIBS])
AC_SUBST([GSSRPC_LIBS])

AC_CHECK_FUNCS([__secure_getenv secure_getenv])

WITH_INITSCRIPT
if test x$initscript = xsystemd; then
    WITH_SYSTEMD_UNIT_DIR
fi

if test x$HAVE_MANPAGES != x; then
    CHECK_XML_TOOLS
    CHECK_STYLESHEET([$SGML_CATALOG_FILES],
                     [http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                     [Docbook XSL templates])
    AC_CHECK_PROG([PO4A],[po4a],[po4a],[no])
fi
AM_CONDITIONAL([HAVE_MANPAGES], [test "x$HAVE_MANPAGES" != "x"])
AM_CONDITIONAL([HAVE_PO4A], [test "x$PO4A" != "xno"])

if test x$HAVE_SELINUX != x; then
    AM_CHECK_SELINUX
fi

if test x$HAVE_SYSTEMD_UNIT != x; then
    AM_CHECK_SYSTEMD
fi

AC_PATH_PROG([DOXYGEN], [doxygen], [false])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x$DOXYGEN != xfalse ])

abs_build_dir=`pwd`
AC_DEFINE_UNQUOTED([ABS_BUILD_DIR], ["$abs_build_dir"], [Absolute path to the build directory])
AC_SUBST([abs_builddir], $abs_build_dir)

AC_CONFIG_FILES([Makefile tests/Makefile man/Makefile
                 contrib/gssproxy.spec
		 man/gssproxy-mech.8.xml])
AC_OUTPUT
