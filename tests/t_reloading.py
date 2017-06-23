#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *
from t_basic import run as run_basic_test

def run(testdir, env, basicconf):
    basicconf['prefix'] = str(cmd_index)
    prefix = basicconf['prefix']
    keysenv = basicconf["keysenv"]

    rets = []

    print("Testing basic SIGHUP with no change", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] += prefix + "_1"
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    r = run_basic_test(testdir, env, basicconf)
    rets.append(r)

    print("Testing SIGHUP with dropped service", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_2"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_MINIMAL_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    r = run_basic_test(testdir, env, basicconf, True)
    rets.append(r)

    print("Testing SIGHUP with new service", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_3"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    r = run_basic_test(testdir, env, basicconf)
    rets.append(r)

    print("Testing SIGHUP with change of socket", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_4"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_SOCKET_TEMPLATE)
    env['GSSPROXY_SOCKET'] += "2"
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    r = run_basic_test(testdir, env, basicconf)
    rets.append(r)

    # restore old configuration
    env['GSSPROXY_SOCKET'] = env['GSSPROXY_SOCKET'][:-1]
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything

    e = [r for r in rets if r != 0]
    if len(e) > 0:
        return e[0]
    return 0

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_reloading.py"])
