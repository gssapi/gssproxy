dnl A macro to check presence of libsystemd on the system
AC_DEFUN([AM_CHECK_SYSTEMD],
[
    PKG_CHECK_MODULES([SYSTEMD_DAEMON],
                      [libsystemd],
                      [AC_DEFINE_UNQUOTED([HAVE_SYSTEMD_DAEMON], 1,
                                          [Build with libsystemd support])
                       HAVE_SYSTEMD_DAEMON=yes
                       AC_MSG_NOTICE([Build with libsystemd support])],
                      [HAVE_SYSTEMD_DAEMON=no
                       AC_MSG_NOTICE([Build without libsystemd support])])

    AM_CONDITIONAL([HAVE_SYSTEMD_DAEMON], [test x"$HAVE_SYSTEMD_DAEMON" = xyes])
])
