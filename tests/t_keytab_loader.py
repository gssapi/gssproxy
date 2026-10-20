#!/usr/bin/python3
# Copyright (C) 2026 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

from t_basic import run as run_basic_test

import os
import testlib

GSSPROXY_KEYTAB_LOADER = '''
[gssproxy]
  debug_level = 3

[service/test]
  mechs = krb5
  cred_store = keytab:MEMORY:${KTNAME}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  keytab_loader = ${PROGDIR}/t_kt_loader ${TESTDIR}/kt_loader.sealed ${TESTDIR}/kt_loader.fail
  trusted = yes
  euid = ${UIDNUMBER}
  allow_client_ccache_sync = yes
'''

# must match T_KT_SEAL_BYTE in t_kt_loader.c
SEAL_BYTE = 0x5a

def seal_keytab(src, dst):
    # gssproxy gets the keys only through t_kt_loader: the sealed file is
    # not a usable keytab
    with open(src, 'rb') as f:
        data = f.read()
    with open(dst, 'wb') as f:
        f.write(bytes(b ^ SEAL_BYTE for b in data))

def set_conf(testdir, conf, ktname):
    text = GSSPROXY_KEYTAB_LOADER.replace("${KTNAME}", ktname)
    update_gssproxy_conf(testdir, conf["keysenv"], text)

def wait_for(testdir, conf, key, sig=0):
    gssproxy_reload(testdir, conf['gpid'], {'signal': sig, 'key': key})

def run_basic(testdir, env, conf, expected_failure=False):
    r = run_basic_test(testdir, env, conf, expected_failure)
    return 1 if r is None else r   # None: timed out

def run(testdir, env, conf):
    conf['prefix'] = str(testlib.cmd_index)
    prefix = conf["prefix"]
    failfile = os.path.join(testdir, "kt_loader.fail")
    retval = 0

    # gssproxy initiates as the service, with the keys of its MEMORY keytab;
    # t_accept plays the remote server with the original keytab
    seal_keytab(conf['keytab'], os.path.join(testdir, "kt_loader.sealed"))

    print("Testing keytab loader...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_1"
    set_conf(testdir, conf, "gp-loaded")
    wait_for(testdir, conf, "Keytab loader for MEMORY:gp-loaded loaded",
             signal.SIGHUP)
    retval |= run_basic(testdir, env, conf)

    print("Testing keytab loader re-run on SIGHUP...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_2"
    wait_for(testdir, conf, "Keytab loader for MEMORY:gp-loaded loaded",
             signal.SIGHUP)
    retval |= run_basic(testdir, env, conf)

    print("Testing failing keytab loader...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_3"
    open(failfile, "w").close()
    set_conf(testdir, conf, "gp-retry")
    wait_for(testdir, conf,
             "Keytab loader for MEMORY:gp-retry exited with status 75",
             signal.SIGHUP)
    retval |= run_basic(testdir, env, conf, expected_failure=True)

    print("Testing keytab loader retry...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_4"
    os.unlink(failfile)
    wait_for(testdir, conf, "Keytab loader for MEMORY:gp-retry loaded")
    retval |= run_basic(testdir, env, conf)

    print("Testing failing re-run keeps the loaded keys...", file=sys.stderr)
    sys.stderr.write("  ")
    conf["prefix"] = prefix + "_5"
    open(failfile, "w").close()
    wait_for(testdir, conf,
             "Keytab loader for MEMORY:gp-retry exited with status 75",
             signal.SIGHUP)
    retval |= run_basic(testdir, env, conf)
    os.unlink(failfile)

    # be a good citizen and clean up after ourselves
    update_gssproxy_conf(testdir, conf["keysenv"], GSSPROXY_CONF_TEMPLATE)
    wait_for(testdir, conf, "Keytab MEMORY:gp-retry is no longer configured",
             signal.SIGHUP)

    print_return(retval, -1, "(%d) Keytab loader" % testlib.cmd_index, False)
    testlib.cmd_index += 1
    return retval

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_keytab_loader.py"])
