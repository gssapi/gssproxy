#!/usr/bin/python3
# Copyright (C) 2015,2016 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

def run(testdir, env, conf, expected_failure=False):
    print("Testing basic acquire creds...", file=sys.stderr)
    logfile = conf['logfile']

    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_acquire", conf['svc_name']]
    print("[COMMAND]\n%s\n[ENVIRONMENT]\n%s\n" % (cmd, env), file=logfile)
    logfile.flush()

    p1 = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid)
    try:
        p1.wait(10)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    print_return(p1.returncode, "Acquire", expected_failure)
    return p1.returncode if not expected_failure else int(not p1.returncode)
