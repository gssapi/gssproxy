#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

def run(testdir, env, conf):
    print("Testing interposer...", file=sys.stderr)
    logfile = conf['logfile']

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

    itest = subprocess.Popen(["./interposetest", "-t",
                              "host@%s" % WRAP_HOSTNAME],
                             stdout=logfile, stderr=logfile,
                             env=ienv)
    itest.wait()
    print_return(itest.returncode, "Interpose", False)
    return itest.returncode
