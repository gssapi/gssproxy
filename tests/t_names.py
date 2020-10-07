#!/usr/bin/python3
# Copyright (C) 2020 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf):
    print("Testing name options...", file=sys.stderr)
    conf['prefix'] = str(cmd_index)
    path_prefix = os.path.join(testdir, 't' + conf['prefix'] + '_')
    init_ccache = path_prefix + 'names_init.ccache'

    logfile = os.path.join(conf['logpath'], "test_%d.log" % cmd_index)
    logfile = open(logfile, 'a')

    testenv = env.copy()
    testenv.update({'KRB5CCNAME': init_ccache})

    usr_keytab = os.path.join(testdir, USR3_KTNAME)
    ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR3_NAME],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError("Kinit %s failed" % USR3_NAME)


    cmd = " ".join(["./tests/t_names", USR3_NAME, HOST_GSS, init_ccache])

    testenv.update({'KRB5CCNAME': path_prefix + 'names.ccache',
                    'KRB5_KTNAME': os.path.join(testdir, SVC_KTNAME),
                    'KRB5_TRACE': path_prefix + 'names.trace',
                    'GSS_USE_PROXY': 'yes',
                    'GSSPROXY_BEHAVIOR': 'REMOTE_ONLY'})

    return run_testcase_cmd(testenv, conf, cmd, "Check Names")

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_names.py"])
