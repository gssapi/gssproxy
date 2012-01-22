AC_PREREQ(2.59)

m4_include([version.m4])
AC_INIT([gssproxy],
        VERSION_NUMBER,
        [simo@redhat.com])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"

AC_CONFIG_SRCDIR([BUILD.txt])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
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

#Include here cause WITH_INIT_DIR requires $osname set in platform.m4
m4_include([external/platform.m4])

m4_include(conf_macros.m4)
WITH_DISTRO_VERSION
WITH_PID_PATH
WITH_LOG_PATH
WITH_PUBCONF_PATH
WITH_PIPE_PATH
WITH_INIT_DIR
WITH_TEST_DIR
WITH_MANPAGES
WITH_XML_CATALOG
WITH_SELINUX

m4_include([external/pkg.m4])
m4_include([external/libpopt.m4])
m4_include([external/krb5.m4])
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

#Check for iniparser
AC_CHECK_HEADERS([iniparser.h],
    [AC_CHECK_LIB(iniparser, iniparser_set, [ INI_LIBS="-liniparser" ],
    [AC_MSG_ERROR([Iniparser library must support iniparser_set])])],
    [AC_MSG_ERROR([Iniparser development package is not installed])]
)

AC_SUBST(INI_LIBS)

AX_PTHREAD(,[AC_MSG_ERROR([Could not find Pthreads support])])

LIBS="$PTHREAD_LIBS $LIBS"
LIBS="$PTHREAD_CFLAGS $CFLAGS"
CC="$PTHREAD_CC"

AC_CHECK_HEADERS([rpc/rpc.h],,[AC_MSG_ERROR([Could not find rpc headers])])

AC_CHECK_HEADERS([gssapi/gssapi.h],,[AC_MSG_ERROR([Could not find GSSAPI headers])])
AC_PATH_PROG(KRB5_CONFIG, krb5-config, failed)
if test x$KRB5_CONFIG = xfailed; then
    AC_MSG_ERROR([Could not find GSSAPI development libraries])
else
    GSSAPI_CFLAGS="`$KRB5_CONFIG --cflags gssapi`"
    GSSAPI_LIBS="`$KRB5_CONFIG --libs gssapi`"
fi

AC_SUBST([GSSAPI_CFLAGS])
AC_SUBST([GSSAPI_LIBS])

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

AC_CONFIG_FILES([Makefile systemd/gssproxy.service man/Makefile])
AC_OUTPUT
