AC_DEFUN([WITH_DISTRO_VERSION],
  [ AC_ARG_WITH([distro-version],
                [AC_HELP_STRING([--with-distro-version=VERSION],
                                [Distro version number []]
                               )
                ]
               )
    AC_DEFINE_UNQUOTED(DISTRO_VERSION, "$with_distro_version",
                           [Distro version number])
  ])

AC_DEFUN([WITH_PID_PATH],
  [ AC_ARG_WITH([pid-path],
                [AC_HELP_STRING([--with-pid-path=PATH],
                                [Where to store pid files for gssproxy [/var/run]]
                               )
                ]
               )
    config_pidpath="\"VARDIR\"/run"
    pidpath="${localstatedir}/run"
    if test x"$with_pid_path" != x; then
        config_pidpath=$with_pid_path
        pidpath=$with_pid_path
    fi
    AC_SUBST(pidpath)
    AC_DEFINE_UNQUOTED(PID_PATH, "$config_pidpath", [Where to store pid files for gssproxy])
  ])

AC_DEFUN([WITH_LOG_PATH],
  [ AC_ARG_WITH([log-path],
                [AC_HELP_STRING([--with-log-path=PATH],
                                [Where to store log files for gssproxy [/var/log/gssproxy]]
                               )
                ]
               )
    config_logpath="\"VARDIR\"/log/gssproxy"
    logpath="${localstatedir}/log/gssproxy"
    if test x"$with_log_path" != x; then
        config_logpath=$with_log_path
        logpath=$with_log_path
    fi
    AC_SUBST(logpath)
    AC_DEFINE_UNQUOTED(LOG_PATH, "$config_logpath", [Where to store log files for gssproxy])
  ])

AC_DEFUN([WITH_PUBCONF_PATH],
  [ AC_ARG_WITH([pubconf-path],
                [AC_HELP_STRING([--with-pubconf-path=PATH],
                                [Where to store pubconf files for gssproxy [/etc/gssproxy]]
                               )
                ]
               )
    config_pubconfpath="\"SYSCONFDIR\"/gssproxy"
    pubconfpath="${sysconfdir}/gssproxy"
    if test x"$with_pubconf_path" != x; then
        config_pubconfpath=$with_pubconf_path
        pubconfpath=$with_pubconf_path
    fi
    AC_SUBST(pubconfpath)
    AC_DEFINE_UNQUOTED(PUBCONF_PATH, "$config_pubconfpath", [Where to store pubconf files for gssproxy])
  ])

AC_DEFUN([WITH_PIPE_PATH],
  [ AC_ARG_WITH([pipe-path],
                [AC_HELP_STRING([--with-pipe-path=PATH],
                                [Where to store pipe files for gssproxy interconnects [/var/lib/gssproxy/pipes]]
                               )
                ]
               )
    config_pipepath="\"VARDIR\"/lib/gssproxy/pipes"
    pipepath="${localstatedir}/lib/gssproxy/pipes"
    if test x"$with_pipe_path" != x; then
        config_pipepath=$with_pipe_path
        pipepath=$with_pipe_path
    fi
    AC_SUBST(pipepath)
    AC_DEFINE_UNQUOTED(PIPE_PATH, "$config_pipepath", [Where to store pipe files for gssproxy interconnects])
  ])

AC_DEFUN([WITH_INITSCRIPT],
  [ AC_ARG_WITH([initscript],
                [AC_HELP_STRING([--with-initscript=INITSCRIPT_TYPE],
                                [Type of your init script (sysv|systemd). [sysv]]
                               )
                ]
               )
  default_initscript=sysv
  if test x"$with_initscript" = x; then
    with_initscript=$default_initscript
  fi

  if test x"$with_initscript" = xsysv || \
     test x"$with_initscript" = xsystemd; then
        initscript=$with_initscript
  else
      AC_MSG_ERROR([Illegal value -$with_initscript- for option --with-initscript])
  fi

  AM_CONDITIONAL([HAVE_SYSV], [test x"$initscript" = xsysv])
  AM_CONDITIONAL([HAVE_SYSTEMD_UNIT], [test x"$initscript" = xsystemd])
  AC_MSG_NOTICE([Will use init script type: $initscript])
  ])

AC_DEFUN([WITH_INIT_DIR],
  [ AC_ARG_WITH([init-dir],
                [AC_HELP_STRING([--with-init-dir=DIR],
                                [Where to store init script for gssproxy [/etc/rc.d/init.d]]
                               )
                ]
               )
    initdir="${sysconfdir}/rc.d/init.d"
    if test x$osname == xgentoo; then
        initdir="${sysconfdir}/init.d"
    fi
    if test x"$with_init_dir" != x; then
        initdir=$with_init_dir
    fi
    AC_SUBST(initdir)
  ])

dnl A macro to configure the directory to install the systemd unit files to
AC_DEFUN([WITH_SYSTEMD_UNIT_DIR],
  [ AC_ARG_WITH([systemdunitdir],
                [ AC_HELP_STRING([--with-systemdunitdir=DIR],
                                 [Directory for systemd service files [Auto]]
                                ),
                ],
               )
  if test x"$with_systemdunitdir" != x; then
    systemdunitdir=$with_systemdunitdir
  else
    systemdunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
    if test x"$systemdunitdir" = x; then
      AC_MSG_ERROR([Could not detect systemd unit directory])
    fi
  fi
  AC_SUBST(systemdunitdir)
  ])

AC_DEFUN([WITH_MANPAGES],
  [ AC_ARG_WITH([manpages],
                [AC_HELP_STRING([--with-manpages],
                                [Whether to regenerate man pages from DocBook sources [yes]]
                               )
                ],
                [],
                with_manpages=yes
               )
    if test x"$with_manpages" = xyes; then
        HAVE_MANPAGES=1
        AC_SUBST(HAVE_MANPAGES)
    fi
  ])
AM_CONDITIONAL([BUILD_MANPAGES], [test x$with_manpages = xyes])

AC_DEFUN([WITH_XML_CATALOG],
  [ AC_ARG_WITH([xml-catalog-path],
                [AC_HELP_STRING([--with-xml-catalog-path=PATH],
                                [Where to look for XML catalog [/etc/xml/catalog]]
                               )
                ]
               )
    SGML_CATALOG_FILES="/etc/xml/catalog"
    if test x"$with_xml_catalog_path" != x; then
        SGML_CATALOG_FILES="$with_xml_catalog_path"
    fi
    AC_SUBST([SGML_CATALOG_FILES])
  ])

AC_DEFUN([WITH_SELINUX],
  [ AC_ARG_WITH([selinux],
                [AC_HELP_STRING([--with-selinux],
                                [Whether to build with SELinux support [yes]]
                               )
                ],
                [],
                with_selinux=yes
               )
    if test x"$with_selinux" = xyes; then
        HAVE_SELINUX=1
        AC_SUBST(HAVE_SELINUX)
        AC_DEFINE_UNQUOTED(HAVE_SELINUX, 1, [Build with SELinux support])
    fi
    AM_CONDITIONAL([BUILD_SELINUX], [test x"$with_selinux" = xyes])
  ])

AC_DEFUN([WITH_TEST_DIR],
  [ AC_ARG_WITH([test-dir],
                [AC_HELP_STRING([--with-test-dir=PATH],
                                [Directory used for make check temporary files [$builddir]]
                               )
                ]
               )
    TEST_DIR=$with_test_dir
    AC_SUBST(TEST_DIR)
    AC_DEFINE_UNQUOTED(TEST_DIR, "$with_test_dir", [Directory used for 'make check' temporary files])
  ])

AC_ARG_ENABLE([all-experimental-features],
              [AS_HELP_STRING([--enable-all-experimental-features],
                              [build all experimental features])],
              [build_all_experimental_features=$enableval],
              [build_all_experimental_features=no])

AC_DEFUN([WITH_CC_PATH],
  [ AC_ARG_WITH([cc-path],
                [AC_HELP_STRING([--with-cc-path=PATH],
                                [Where to store ccache files for gssproxy [/var/run/user/gssproxy]]
                               )
                ]
               )
    config_ccpath="\"VARDIR\"/run/user/gssproxy"
    ccpath="${localstatedir}/run/user/gssproxy"
    if test x"$with_cc_path" != x; then
        config_ccpath=$with_cc_path
        ccpath=$with_cc_path
    fi
    AC_SUBST(ccpath)
    AC_DEFINE_UNQUOTED(CCACHE_PATH, "$config_ccpath", [Where to store ccache files for gssproxy])
  ])

