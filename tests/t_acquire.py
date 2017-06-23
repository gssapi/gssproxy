#!/usr/bin/python3
# Copyright (C) 2015,2016 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

def run(testdir, env, conf, expected_failure=False):
    print("Testing basic acquire creds...", file=sys.stderr)
    conf['prefix'] = str(cmd_index)

    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = "./tests/t_acquire " + conf['svc_name']

    return run_testcase_cmd(testenv, conf, cmd, "Acquire", expected_failure)

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_acquire.py"])
