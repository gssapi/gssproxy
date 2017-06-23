#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf):
    print("Testing interposer...", file=sys.stderr)
    conf['prefix'] = str(cmd_index)
    logfile = os.path.join(conf['logpath'], "test_%d.log" % cmd_index)
    logfile = open(logfile, 'a')

    ienv = {"KRB5CCNAME": os.path.join(testdir, 'interpose_ccache'),
            "KRB5_KTNAME": os.path.join(testdir, SVC_KTNAME)}
    ienv.update(env)
    usr_keytab = os.path.join(testdir, USR_KTNAME)

    ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab, USR_NAME],
                              stdout=logfile, stderr=logfile,
                              env=ienv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('Kinit %s failed' % USR_NAME)

    cmd = " ".join(["./interposetest", "-t", "host@%s" % WRAP_HOSTNAME])
    return run_testcase_cmd(ienv, conf, cmd, "Interpose")

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_interpose.py"])
