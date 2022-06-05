dnl A macro to check presence of systemd on the system
AC_DEFUN([AM_CHECK_SYSTEMD],
[
    PKG_CHECK_EXISTS([systemd],
                     [HAVE_SYSTEMD=yes],
                     [HAVE_SYSTEMD=no])

    dnl older system uses libsystemd
    PKG_CHECK_EXISTS([libsystemd],
                     [HAVE_LIBSYSTEMD=yes],
                     [HAVE_LIBSYSTEMD=no])
    dnl newer systemd splits libsystemd in slaler libs
    AS_IF([test x$HAVE_LIBSYSTEMD = xyes],
          [daemon_lib_name=libsystemd],
          [daemon_lib_name=libsystemd-daemon])

    AS_IF([test x$HAVE_SYSTEMD = xyes],
          [PKG_CHECK_MODULES(
              [SYSTEMD_DAEMON],
              [$daemon_lib_name],
              [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD_DAEMON], 1,
                                  [Build with $daemon_lib_name support])

               AC_MSG_NOTICE([Will enable systemd socket activation])],
              [AC_MSG_NOTICE([Build without $daemon_lib_name support])])],
          [AC_MSG_NOTICE([Build without $daemon_lib_name support])])

    AM_CONDITIONAL([HAVE_SYSTEMD_DAEMON], [test x"$daemon_lib_name" != x])
])
