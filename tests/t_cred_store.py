#!/usr/bin/python3
# Copyright (C) 2016 - GSS-Proxy contributors; see COPYING for the license.

from testlib import *

def run(testdir, env, conf):
    print("Testing cred store extensions...", file=sys.stderr)
    conf['prefix'] = str(cmd_index)

    logfile = os.path.join(conf["logpath"], "test_%d.log" % cmd_index)
    logfile = open(logfile, 'a')

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
    cmd = " ".join(["./tests/t_cred_store", ccache, temp_ccache])

    return run_testcase_cmd(testenv, conf, cmd, "Cred store")

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_cred_store.py"])
