#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license.

import argparse
import importlib
import signal
import subprocess
import sys
import traceback

import testlib
from testlib import *

def check_exec(name):
    env = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin'}
    ret = subprocess.call(["which", name], stdout=subprocess.DEVNULL, env=env)
    if ret != 0:
        print(f"Executable '{name}' not found in {env['PATH']}",
              file=sys.stderr)
        exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description='GSS-Proxy Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")
    parser.add_argument('--debug-all', default=False, action="store_true",
                        help="Enable debugging for all test cases")
    parser.add_argument('--debug-gssproxy', default=False, action="store_true",
                        help="Enable debugging for gssproxy command")
    parser.add_argument('--debug-cmd', default="gdb --args",
                        help="Set the debugging command. Defaults to gdb " +
                              "--args")
    parser.add_argument('--debug-num', default=-1, type=int,
                        help="Specify the testcase number to debug")
    parser.add_argument('--timeout', default=15, type=int,
                        help="Specify test case timeout limit")
    parser.add_argument('--valgrind-cmd', default="valgrind " +
                        "--track-origins=yes",
                        help="Set the valgrind command. Defaults to " +
                        "valgrind --track-origins=yes")
    parser.add_argument('--force-valgrind', default=False, action="store_true",
                        help="Force valgrind to be run on all test cases")

    args = vars(parser.parse_args())
    testlib_process_args(args)

    return args

def runtests_main(testfiles):
    args = parse_args()

    for e in ["bash", "pkg-config", "zcat", "kinit", "krb5kdc", "kdb5_util",
             "kadmin.local", "kdb5_ldap_util", "slapd", "slapadd",
              "ldapmodify", "valgrind"]:
        check_exec(e)

    testdir = args['path']
    if os.path.exists(testdir):
        shutil.rmtree(testdir)
    os.makedirs(testdir)

    processes = dict()

    errored = False

    try:
        wrapenv = setup_wrappers(testdir)
        write_ldap_krb5_config(testdir)

        ldapproc, ldapenv = setup_ldap(testdir, wrapenv)
        processes["LDAP(%d)" % ldapproc.pid] = ldapproc

        kdcproc, kdcenv = setup_kdc(testdir, wrapenv)
        processes['KDC(%d)' % kdcproc.pid] = kdcproc

        keysenv = setup_keys(testdir, kdcenv)

        gssapienv = setup_gssapi_env(testdir, kdcenv)

        if 'TERM' in os.environ:
            gssapienv['TERM'] = os.environ['TERM']

        gssproxylog = os.path.join(testdir, 'gssproxy.log')

        logfile = open(gssproxylog, "a")

        gssproxyenv = keysenv
        gssproxyenv['KRB5_TRACE'] = os.path.join(testdir, 'gssproxy.trace')

        gproc, gpsocket = setup_gssproxy(testdir, logfile, gssproxyenv)
        time.sleep(5) #Give time to gssproxy to fully start up
        processes['GSS-Proxy(%d)' % gproc.pid] = gproc
        gssapienv['GSSPROXY_SOCKET'] = gpsocket

        basicconf = {'svc_name': "host@%s" % WRAP_HOSTNAME,
                     'keytab': os.path.join(testdir, SVC_KTNAME)}
        basicconf["gpid"] = gproc.pid
        basicconf["keysenv"] = keysenv

        print("Tests to be run: " + ", ".join(testfiles))
        for f in testfiles:
            fmod = f[:-len(".py")]
            t = importlib.__import__(fmod)

            basicconf['prefix'] = str(testlib.cmd_index)
            basicconf['logpath'] = testdir
            r = t.run(testdir, gssapienv, basicconf)
            if r != 0:
                errored = True
    except Exception:
        traceback.print_exc()
        errored = True
    finally:
        for name in processes:
            print("Killing %s" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)

        if errored:
            sys.exit(1)
        sys.exit(0)

if __name__ == "__main__":
    print("\n")
    print("To pass arguments to the test suite, use CHECKARGS:")
    print("    make check CHECKARGS='--debug-num=<num>'")
    print("A full set of available options can be seen with --help")
    print("\n")

    testfiles = [f for f in os.listdir(os.path.dirname(sys.argv[0])) \
                 if f.endswith(".py") and f.startswith("t_")]
    testfiles.sort()
    runtests_main(testfiles)
