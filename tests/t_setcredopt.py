#!/usr/bin/python3
# Copyright (C) 2017 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf):
    print("Testing setting credential options...", file=sys.stderr)
    path_prefix = os.path.join(testdir, 't' + conf['prefix'] + '_')
    init_ccache = path_prefix + 'sco_init.ccache'

    logfile = conf['logfile']
    testenv = env.copy()
    testenv.update({'KRB5CCNAME': init_ccache})

    usr_keytab = os.path.join(testdir, USR_KTNAME)
    ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR_NAME],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError("Kinit %s failed" % USR_NAME)


    cmd = ["./tests/t_setcredopt", USR_NAME, HOST_GSS, init_ccache]

    testenv.update({'KRB5CCNAME': path_prefix + 'sco.ccache',
                    'KRB5_KTNAME': os.path.join(testdir, PROXY_KTNAME),
                    'KRB5_TRACE': path_prefix + 'sco.trace',
                    'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'})

    print("[COMMAND]\n%s\n[ENVIRONMENT]\n%s\n" % (cmd, testenv), file=logfile)
    logfile.flush()

    p1 = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid)
    try:
        p1.wait(10)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    print_return(p1.returncode, "Set cred options", False)
    return p1.returncode
