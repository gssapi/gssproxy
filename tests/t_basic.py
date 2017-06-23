#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

import testlib
import os
import signal
import subprocess
import sys


def run(testdir, env, conf, expected_failure=False):
    print("Testing basic init/accept context", file=sys.stderr)
    conf['prefix'] = str(testlib.cmd_index)

    init_logfile = os.path.join(conf['logpath'], "test_%d.log" %
                                testlib.cmd_index)
    init_logfile = open(init_logfile, 'a')

    accept_logfile = os.path.join(conf['logpath'], "test_%d.log" %
                                  (testlib.cmd_index + 1))
    accept_logfile = open(accept_logfile, 'a')

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

    init_cmd = " ".join(init_cmd)
    accept_cmd = " ".join(["./tests/t_accept"])

    clienv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.trace'),
              'GSS_USE_PROXY': 'yes',
              'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    clienv.update(env)

    print("[CLIENV]\n%s\nCLI NAME: %s\n" % (
          clienv, client_name), file=init_logfile)

    print("[SRVENV]\n%s\n" % (svcenv), file=accept_logfile)

    init_logfile.flush()
    accept_logfile.flush()

    pipe0 = os.pipe()
    pipe1 = os.pipe()

    if testlib.debug_cmd_index == testlib.cmd_index:
        p1 = subprocess.Popen(init_cmd,
                              stdin=pipe0[0], stdout=pipe1[1],
                              stderr=init_logfile, env=clienv,
                              preexec_fn=os.setsid, shell=True,
                              executable="/bin/bash")
        print("PID: %d\n" % p1.pid)
        print("Attach and start debugging, then press enter to start t_init.")
        input()

        p2 = subprocess.Popen(["./tests/t_accept"],
                              stdin=pipe1[0], stdout=pipe0[1],
                              stderr=accept_logfile, env=svcenv,
                              preexec_fn=os.setsid, shell=True,
                              executable="/bin/bash")
        print("To resume tests if hung, kill pid %d\n" % p2.pid)
        p2.wait()

        init_logfile.close()
        accept_logfile.close()

        testlib.cmd_index += 2
        return int(expected_failure)
    elif testlib.debug_cmd_index == testlib.cmd_index+1:
        p2 = subprocess.Popen(["./tests/t_accept"],
                              stdin=pipe1[0], stdout=pipe0[1],
                              stderr=accept_logfile, env=svcenv,
                              preexec_fn=os.setsid, shell=True,
                              executable="/bin/bash")
        print("PID: %d\n" % p2.pid)
        print("Attach and start debugging, then press enter to start t_init.")
        input()

        p1 = subprocess.Popen(init_cmd,
                              stdin=pipe0[0], stdout=pipe1[1],
                              stderr=init_logfile, env=clienv,
                              preexec_fn=os.setsid, shell=True,
                              executable="/bin/bash")
        print("To resume tests if hung, kill pid %d\n" % p1.pid)
        p1.wait()

        init_logfile.close()
        accept_logfile.close()

        testlib.cmd_index += 2
        return int(expected_failure)

    if testlib.valgrind_everywhere:
        accept_cmd = testlib.valgrind_cmd + accept_cmd
        init_cmd = testlib.valgrind_cmd + init_cmd
    p2 = subprocess.Popen(accept_cmd,
                          stdin=pipe1[0], stdout=pipe0[1],
                          stderr=accept_logfile, env=svcenv,
                          preexec_fn=os.setsid, shell=True,
                          executable="/bin/bash")
    p1 = subprocess.Popen(init_cmd,
                          stdin=pipe0[0], stdout=pipe1[1],
                          stderr=init_logfile, env=clienv,
                          preexec_fn=os.setsid, shell=True,
                          executable="/bin/bash")

    try:
        p1.wait(testlib.testcase_wait)
        p2.wait(testlib.testcase_wait)
    except subprocess.TimeoutExpired:
        # {p1,p2}.returncode are set to None here
        if not expected_failure:
            testlib.print_warning("warning", "timeout")
    init_logfile.close()
    accept_logfile.close()
    testlib.print_return(p1.returncode, testlib.cmd_index,
                         "(%d) Init" % testlib.cmd_index,
                         expected_failure)
    testlib.print_return(p2.returncode, testlib.cmd_index + 1,
                         "(%d) Accept" % (testlib.cmd_index + 1),
                         expected_failure)
    testlib.cmd_index += 2
    try:
        os.killpg(p1.pid, signal.SIGTERM)
        os.killpg(p2.pid, signal.SIGTERM)
    except OSError:
        pass
    if p1.returncode != 0:
        return p1.returncode if not expected_failure else int(not p1.returncode)
    elif p2.returncode != 0:
        return p2.returncode if not expected_failure else int(not p2.returncode)
    return int(expected_failure)

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_basic.py"])
