#!/usr/bin/python3
# Copyright (C) 2017 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf):
    print("Testing setting credential options...", file=sys.stderr)
    conf['prefix'] = str(cmd_index)
    path_prefix = os.path.join(testdir, 't' + conf['prefix'] + '_')
    init_ccache = path_prefix + 'sco_init.ccache'

    logfile = os.path.join(conf['logpath'], "test_%d.log" % cmd_index)
    logfile = open(logfile, 'a')

    testenv = env.copy()
    testenv.update({'KRB5CCNAME': init_ccache})

    usr_keytab = os.path.join(testdir, USR_KTNAME)
    ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR_NAME],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError("Kinit %s failed" % USR_NAME)


    cmd = " ".join(["./tests/t_setcredopt", USR_NAME, HOST_GSS, init_ccache])

    testenv.update({'KRB5CCNAME': path_prefix + 'sco.ccache',
                    'KRB5_KTNAME': os.path.join(testdir, PROXY_KTNAME),
                    'KRB5_TRACE': path_prefix + 'sco.trace',
                    'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'})

    return run_testcase_cmd(testenv, conf, cmd, "Set cred options")

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_setcredopt.py"])
