#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf, expected_failure=False):
    print("Testing basic init/accept context", file=sys.stderr)
    logfile = conf['logfile']

    svcenv = {'KRB5_KTNAME': conf['keytab'],
              'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_accept.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_accept.trace')}
    svcenv.update(env)

    client_name = conf.get('client_name', None)
    if client_name is not None:
        init_cmd = ["./tests/t_init", conf['svc_name'], client_name]
    else:
        init_cmd = ["./tests/t_init", conf['svc_name']]

    clienv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.trace'),
              'GSS_USE_PROXY': 'yes',
              'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    clienv.update(env)

    print("[SVCENV]\n%s\n[CLIENV]\n%s\nCLI NAME: %s\n" % (
          svcenv, clienv, client_name), file=logfile)

    pipe0 = os.pipe()
    pipe1 = os.pipe()

    p1 = subprocess.Popen(init_cmd,
                          stdin=pipe0[0], stdout=pipe1[1],
                          stderr=logfile, env=clienv, preexec_fn=os.setsid)
    p2 = subprocess.Popen(["./tests/t_accept"],
                          stdin=pipe1[0], stdout=pipe0[1],
                          stderr=logfile, env=svcenv, preexec_fn=os.setsid)

    try:
        p1.wait(30)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    if p1.returncode != 0 and not expected_failure:
        print_failure("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Init test returned %s" % str(p1.returncode))
        try:
            os.killpg(p2.pid, signal.SIGTERM)
        except OSError:
            pass
    else:
        print_success("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Init test returned %s" % str(p1.returncode))
    try:
        p2.wait(30)
    except subprocess.TimeoutExpired:
        # p2.returncode is set to None here
        pass
    if p2.returncode != 0 and not expected_failure:
        print_failure("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Accept test returned %s" % str(p2.returncode))
        try:
            os.killpg(p1.pid, signal.SIGTERM)
        except OSError:
            pass
    else:
        print_success("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Accept test returned %s" % str(p2.returncode))
