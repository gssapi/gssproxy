#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *
from t_basic import run as run_basic_test

def run(testdir, env, basicconf):
    prefix = basicconf['prefix']
    keysenv = basicconf["keysenv"]

    print("Testing basic SIGHUP with no change", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] += prefix + "_1"
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, basicconf)

    print("Testing SIGHUP with dropped service", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_2"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_MINIMAL_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, basicconf, True)

    print("Testing SIGHUP with new service", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_3"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, basicconf)

    print("Testing SIGHUP with change of socket", file=sys.stderr)
    sys.stderr.write("  ")
    basicconf['prefix'] = prefix + "_4"
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_SOCKET_TEMPLATE)
    env['GSSPROXY_SOCKET'] += "2"
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
    run_basic_test(testdir, env, basicconf)

    # restore old configuration
    env['GSSPROXY_SOCKET'] = env['GSSPROXY_SOCKET'][:-1]
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    os.kill(basicconf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything
