#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license.

import argparse
import signal

from testlib import *

def parse_args():
    parser = argparse.ArgumentParser(description='GSS-Proxy Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")

    return vars(parser.parse_args())

def run_interposetest(testdir, env):
    testlog = os.path.join(testdir, 'interposetest.log')

    ienv = {"KRB5CCNAME": os.path.join(testdir, 'interpose_ccache'),
            "KRB5_KTNAME": os.path.join(testdir, SVC_KTNAME)}
    ienv.update(env)
    usr_keytab = os.path.join(testdir, USR_KTNAME)
    with (open(testlog, 'a')) as logfile:
        ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR_NAME],
                                  stdout=logfile, stderr=logfile,
                                  env=ienv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('Kinit %s failed' % USR_NAME)

    with (open(testlog, 'a')) as logfile:
        itest = subprocess.Popen(["./interposetest", "-t",
                                  "host@%s" % WRAP_HOSTNAME],
                                 stdout=logfile, stderr=logfile,
                                 env=ienv)
    itest.wait()
    if itest.returncode != 0:
        raise ValueError('Interposetest failed')

def run_basic_test(testdir, env, conf, expected_failure=False):

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


def run_acquire_test(testdir, env, conf, expected_failure=False):

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
        p1.wait(30)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    if p1.returncode != 0 and not expected_failure:
        print_failure("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Acquire test returned %s" % str(p1.returncode))
    else:
        print_success("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Acquire test returned %s" % str(p1.returncode))


def run_impersonate_test(testdir, env, conf, expected_failure=False):

    logfile = conf['logfile']

    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_impersonate", USR_NAME, conf['svc_name']]
    print("[COMMAND]\n%s\n[ENVIRONMENT]\n%s\n" % (cmd, env), file=logfile)
    logfile.flush()

    p1 = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid)
    try:
        p1.wait(30)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    if p1.returncode != 0 and not expected_failure:
        print_failure("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Impersonate test returned %s" % str(p1.returncode))
    else:
        print_success("SUCCESS" if p1.returncode == 0 else "FAILED",
                      "Impersonate test returned %s" % str(p1.returncode))


if __name__ == '__main__':

    args = parse_args()

    testdir = args['path']
    if os.path.exists(testdir):
        shutil.rmtree(testdir)
    os.makedirs(testdir)

    processes = dict()

    try:
        wrapenv = setup_wrappers(testdir)

        ldapproc, ldapenv = setup_ldap(testdir, wrapenv)
        processes["LDAP(%d)" % ldapproc.pid] = ldapproc

        kdcproc, kdcenv = setup_kdc(testdir, wrapenv)
        processes['KDC(%d)' % kdcproc.pid] = kdcproc

        keysenv = setup_keys(testdir, kdcenv)

        gssapienv = setup_gssapi_env(testdir, kdcenv)

        run_interposetest(testdir, gssapienv)

        gssproxylog = os.path.join(testdir, 'gssproxy.log')
        with (open(gssproxylog, 'a')) as logfile:
            gproc, gpsocket = setup_gssproxy(testdir, logfile, keysenv)
            time.sleep(5) #Give time to gssproxy to fully start up
            processes['GSS-Proxy(%d)' % gproc.pid] = gproc
            gssapienv['GSSPROXY_SOCKET'] = gpsocket

            basicconf = {'svc_name': "host@%s" % WRAP_HOSTNAME,
                         'keytab': os.path.join(testdir, SVC_KTNAME)}

            # Test 01
            testnum = 1
            print("Testing basic acquire creds", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir,
                                  '%02d_basic_acquire.log' % testnum), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_acquire_test(testdir, gssapienv, basicconf)

            # Test 02
            testnum += 1
            print("Testing impersonate creds", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir, '02_impersonate.log'), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_impersonate_test(testdir, gssapienv, basicconf)

            # Test 03
            testnum += 1
            print("Testing basic init/accept context", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir, '03_basic_exchange.log'), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 1)
            testnum += 1
            basicconf['logfile'] = \
                open(os.path.join(testdir, '04_sighups.log'), 'a')

            print("Testing basic SIGHUP with no change", file=sys.stderr)
            basicconf['prefix'] = '%02d_1' % testnum
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 2)
            print("Testing SIGHUP with dropped service", file=sys.stderr)
            basicconf['prefix'] = '%02d_2' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_MINIMAL_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf, True)

            # Test 04 (part 3)
            print("Testing SIGHUP with new service", file=sys.stderr)
            basicconf['prefix'] = '%02d_3' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 4)
            print("Testing SIGHUP with change of socket", file=sys.stderr)
            basicconf['prefix'] = '%02d_4' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_SOCKET_TEMPLATE)
            gssapienv['GSSPROXY_SOCKET'] += "2"
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 05 (part 1)
            testnum += 1
            basicconf['logfile'] = \
                open(os.path.join(testdir, '05_multiple-keys.log'), 'a')
            setup_multi_keys(testdir, gssapienv)
            gssapienv['GSSPROXY_SOCKET'] = gpsocket

            # Q: What are we testing here ?
            # A: A client calling gss_init_sec_context() w/o explicitly
            # acquiring credentials before hand. [Note: in this case
            # gssproxy uses the 'keytab' specified in the store and ignores
            # the 'client_keytab' one].
            # A gssproxy configruation where the keytab containes multiple
            # keys, and a krb5_principal option that sepcify what name we
            # want to use.
            # We try both names to make sure we target a specific key and not
            # just pick up the first in the keytab (which is the normal
            # behavior).

            print("Testing multiple keys Keytab with first principal",
                  file=sys.stderr)
            if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
                os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
            basicconf['prefix'] = '%02d_1' % testnum
            p1env = {}
            p1env.update(keysenv)
            p1env['client_name'] = MULTI_UPN
            p1env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
            update_gssproxy_conf(testdir, p1env, GSSPROXY_MULTI_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 2)
            print("Testing multiple keys Keytab with second principal",
                  file=sys.stderr)
            if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
                os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
            basicconf['prefix'] = '%02d_2' % testnum
            p2env = {}
            p2env.update(keysenv)
            p2env['client_name'] = MULTI_SVC
            p2env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
            update_gssproxy_conf(testdir, p2env, GSSPROXY_MULTI_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)
    finally:
        for name in processes:
            print("Killing %s" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)
