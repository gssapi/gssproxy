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

AC_DEFUN([WITH_SOCKET_NAME],
  [ AC_ARG_WITH([socket-name],
                [AC_HELP_STRING([--with-socket-name=PATH],
                                [Name of the GSS Proxy socket file [/var/lib/gssproxy/default.sock]]
                               )
                ]
               )
    gp_socket_name="\"VARDIR\"/lib/gssproxy/default.sock"
    socketname="${localstatedir}/lib/gssproxy/default.sock"
    if test x"$with_socket_name" != x; then
        gp_socket_name=$with_socket_name
        socketname=$with_socket_name
    fi
    AC_SUBST(socketname)
    AC_DEFINE_UNQUOTED(GP_SOCKET_NAME, "$gp_socket_name", [The name of the GSS Proxy socket file])
  ])

AC_DEFUN([WITH_PID_FILE],
  [ AC_ARG_WITH([pid-file],
                [AC_HELP_STRING([--with-id-file=PATH],
                                [Name of the GSS Proxy pid file [/var/run/gssproxy.pid]]
                               )
                ]
               )
    gp_pid_file="\"VARDIR\"/run/gssproxy.pid"
    pidfile="${localstatedir}/run/gssproxy.pid"
    if test x"$with_pid_file" != x; then
        gp_pid_file=$with_pid_file
        pidfile=$with_pid_file
    fi
    AC_SUBST(pidfile)
    AC_DEFINE_UNQUOTED(GP_PID_FILE, "$gp_pid_file", [The name of the GSS Proxy pid file])
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

AC_DEFUN([WITH_GPSTATE_PATH],
  [ AC_ARG_WITH([gpstate-path],
                [AC_HELP_STRING([--with-gpstate-path=PATH],
                                [Where to create default socket for gssproxy [/var/lib/gssproxy]]
                               )
                ]
               )
    config_gpstatepath="\"VARDIR\"/lib/gssproxy"
    gpstatedir="${localstatedir}/lib/gssproxy"
    if test x"$with_gpstate_path" != x; then
        config_gpstatepath=$with_gpstate_path
        gpstatepath=$with_gpstate_path
    fi
    AC_SUBST(gpstatedir)
    AC_DEFINE_UNQUOTED(GPSTATE_PATH, "$config_gpstatepath", [Where to store ccache files for gssproxy])
  ])

AC_DEFUN([WITH_GSSIDEBUG],
  [ AC_ARG_WITH([gssidebug],
                [AC_HELP_STRING([--with-gssidebug],
                                [Whether to build with interposer debugging support [no]]
                               )
                ],
                [],
                with_gssidebug=no
               )
    if test x"$with_gssidebug" = xyes; then
        AC_DEFINE_UNQUOTED(GSSI_DEBUGGING, 1, [Build with interposer debugging support])
    fi
  ])

AC_DEFUN([WITH_GPP_DEFAULT_BEHAVIOR],
  [ AC_ARG_WITH([gpp_default_behavior],
                [AC_HELP_STRING([--with-gpp-default-behavior=LOCAL_FIRST|LOCAL_ONLY|REMOTE_FIRST|REMOTE_ONLY],
                                [Which default behavior the gssproxy interposer plugin should use [LOCAL_FIRST]]
                               )
                ],
                [],
               )
    default_behavior=GPP_LOCAL_FIRST
    default_behavior_env=LOCAL_FIRST
    if test x"$with_gpp_default_behavior" = x"LOCAL_FIRST"; then
        AC_MSG_RESULT([Using gssproxy interposer behavior LOCAL_FIRST])
	default_behavior=GPP_LOCAL_FIRST
	default_behavior_env=LOCAL_FIRST
    elif test x"$with_gpp_default_behavior" = x"LOCAL_ONLY"; then
        AC_MSG_RESULT([Using gssproxy interposer behavior LOCAL_ONLY])
        default_behavior=GPP_LOCAL_ONLY
	default_behavior_env=LOCAL_ONLY
    elif test x"$with_gpp_default_behavior" = x"REMOTE_FIRST"; then
        AC_MSG_RESULT([Using gssproxy interposer behavior REMOTE_FIRST])
        default_behavior=GPP_REMOTE_FIRST
	default_behavior_env=REMOTE_FIRST
    elif test x"$with_gpp_default_behavior" = x"REMOTE_ONLY"; then
        AC_MSG_ERROR([REMOTE_ONLY currently not supported])
    elif test x"$with_gpp_default_behavior" != x; then
        AC_MSG_ERROR([unknown gpp default behavior])
    fi
    AC_SUBST(GPP_DEFAULT_BEHAVIOR, $default_behavior_env)
    AC_DEFINE_UNQUOTED(GPP_DEFAULT_BEHAVIOR, $default_behavior, [Default gssproxy interposer plugin behavior])
  ])

