#!/usr/bin/python3
# Copyright (C) 2015,2016 - GSS-Proxy contributors; see COPYING for the license

from testlib import *

IMPERSONATE_CONF_TEMPLATE = '''
[gssproxy]
  debug_level = 2

[service/impersonate]
  socket = ${TESTDIR}/impersonate.socket
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  allow_protocol_transition = yes
  allow_constrained_delegation = yes
  euid = ${UIDNUMBER}

[service/selfonly]
  socket = ${TESTDIR}/impersonate-selfonly.socket
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  allow_protocol_transition = yes
  euid = ${UIDNUMBER}

[service/proxyonly]
  socket = ${TESTDIR}/impersonate-proxyonly.socket
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  allow_constrained_delegation = yes
  euid = ${UIDNUMBER}

'''

def run_cmd(testdir, env, conf, name, socket, cmd, expected_failure):

    logfile = conf['logfile']
    testenv = env.copy()
    testenv.update({'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                               '_impersonate.ccache'),
                    'KRB5_KTNAME': os.path.join(testdir, PROXY_KTNAME),
                    'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                               '_impersonate.trace'),
                    'GSS_USE_PROXY': 'yes',
                    'GSSPROXY_SOCKET': socket,
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
    print_return(p1.returncode, name, expected_failure)
    return p1.returncode if not expected_failure else int(not p1.returncode)

def run(testdir, env, conf):
    print("Testing impersonate creds...", file=sys.stderr)
    path_prefix = os.path.join(testdir, 't' + conf['prefix'] + '_')

    # Change gssproxy conf for our test
    keysenv = conf["keysenv"].copy()
    keysenv['KRB5_KTNAME'] = os.path.join(testdir, PROXY_KTNAME)
    update_gssproxy_conf(testdir, keysenv, IMPERSONATE_CONF_TEMPLATE)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything

    rets = []

    # Test all permitted
    socket = os.path.join(testdir, 'impersonate.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache']
    r = run_cmd(testdir, env, conf, "Impersonate", socket, cmd, False)
    rets.append(r)

    #Test fail
    socket = os.path.join(testdir, 'impersonate-proxyonly.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache']
    r = run_cmd(testdir, env, conf, "Impersonate fail self", socket, cmd, True)
    rets.append(r)

    #Test fail
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache']
    r = run_cmd(testdir, env, conf, "Impersonate fail proxy", socket, cmd, True)
    rets.append(r)

    #Test s4u2self half succeed
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache', 's4u2self']
    r = run_cmd(testdir, env, conf, "s4u2self delegation", socket, cmd, False)
    rets.append(r)

    #Test s4u2proxy half fail
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache', 's4u2proxy']
    r = run_cmd(testdir, env, conf, "s4u2proxy fail", socket, cmd, True)
    rets.append(r)

    #Test s4u2proxy half succeed
    socket = os.path.join(testdir, 'impersonate-proxyonly.socket')
    cmd = ["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
           path_prefix + 'impersonate.cache', 's4u2proxy']
    r = run_cmd(testdir, env, conf, "s4u2proxy", socket, cmd, False)
    rets.append(r)

    # Reset back gssproxy conf
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    os.kill(conf["gpid"], signal.SIGHUP)
    time.sleep(1) #Let gssproxy reload everything

    e = [r for r in rets if r != 0]
    if len(e) > 0:
        return e[0]
    return 0
