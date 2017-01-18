#!/usr/bin/python3
# Copyright (C) 2016 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

def run(testdir, env, conf):
    print("Testing cred store extensions...", file=sys.stderr)
    logfile = conf["logfile"]

    ccache = "FILE:" + os.path.join(testdir, "t" + conf["prefix"] +
                                    "_cred_store.ccache")
    testenv = {"KRB5CCNAME": ccache}
    testenv.update(env)
    usr_keytab = os.path.join(testdir, USR_KTNAME)
    ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR_NAME],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError("Kinit %s failed" % USR_NAME)

    testenv = {"KRB5_TRACE": os.path.join(testdir,
                                          "t" + conf["prefix"] + ".trace"),
               "GSS_USE_PROXY": "yes",
               "GSSPROXY_BEHAVIOR": "REMOTE_FIRST"}
    testenv.update(env)
    temp_ccache = "FILE:" + os.path.join(testdir, "t" + conf["prefix"] +
                                         "_temp.ccache")
    cmd = ["./tests/t_cred_store", ccache, temp_ccache]
    print("[COMMAND]\n%s\n[ENVIRONMENT]\n%s\n" % (cmd, testenv), file=logfile)
    logfile.flush()

    p1 = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid)
    try:
        p1.wait()
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        pass
    print_return(p1.returncode, "Cred store", False)
    return p1.returncode
