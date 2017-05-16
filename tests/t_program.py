#!/usr/bin/python3
# Copyright (C) 2017 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

from t_acquire import run as run_acquire_test

import os

GSSPROXY_PROGRAM = '''
[gssproxy]
  debug_level = 3

[service/t_acquire]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = ${UIDNUMBER}
  allow_client_ccache_sync = yes
  program = ${PROGDIR}/t_acquire
'''

def run(testdir, env, conf):
    prefix = conf["prefix"]
    retval = 0

    print("Testing positive program name matching...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_1"
    update_gssproxy_conf(testdir, conf["keysenv"], GSSPROXY_PROGRAM)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1)
    retval |= run_acquire_test(testdir, env, conf)

    print("Testing negative program name matching...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_2"
    bad_progdir = GSSPROXY_PROGRAM.replace("${PROGDIR}", "//bad/path")
    update_gssproxy_conf(testdir, conf["keysenv"], bad_progdir)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1)
    retval |= run_acquire_test(testdir, env, conf, expected_failure=True)

    # be a good citizen and clean up after ourselves
    update_gssproxy_conf(testdir, conf["keysenv"], GSSPROXY_CONF_TEMPLATE)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1)

    print_return(retval, "Program", False)
    return retval
