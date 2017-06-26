#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license.

import argparse
import importlib
import signal
import sys
import traceback

from testlib import *

def parse_args():
    parser = argparse.ArgumentParser(description='GSS-Proxy Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")

    return vars(parser.parse_args())

if __name__ == '__main__':
    args = parse_args()

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

        testnum = 0
        testfiles = [f for f in os.listdir(os.path.dirname(sys.argv[0])) \
                     if f.endswith(".py") and f.startswith("t_")]
        testfiles.sort()
        print("Tests to be run: " + ", ".join(testfiles))
        for f in testfiles:
            fmod = f[:-len(".py")]
            t = importlib.__import__(fmod)

            basicconf['prefix'] = '%02d' % testnum
            logfile = os.path.join(testdir, "%02d_%s.log" % (testnum, fmod))
            basicconf['logfile'] = open(logfile, 'a')
            r = t.run(testdir, gssapienv, basicconf)
            if r != 0:
                errored = True

            testnum += 1
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
