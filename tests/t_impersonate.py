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

def run_cmd(testdir, env, conf, name, socket, cmd, keytab, expected_failure):
    conf['prefix'] = str(cmd_index)
    testenv = env.copy()
    testenv.update({'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                               '_impersonate.ccache'),
                    'KRB5_KTNAME': os.path.join(testdir, keytab),
                    'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                               '_impersonate.trace'),
                    'GSS_USE_PROXY': 'yes',
                    'GSSPROXY_SOCKET': socket,
                    'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'})

    return run_testcase_cmd(testenv, conf, cmd, name, expected_failure)

def run(testdir, env, conf):
    print("Testing impersonate creds...", file=sys.stderr)
    path_prefix = os.path.join(testdir, 't' + conf['prefix'] + '_')

    # Change gssproxy conf for our test
    keysenv = conf["keysenv"].copy()
    keysenv['KRB5_KTNAME'] = os.path.join(testdir, PROXY_KTNAME)
    update_gssproxy_conf(testdir, keysenv, IMPERSONATE_CONF_TEMPLATE)
    gssproxy_reload(testdir, conf['gpid'])

    rets = []

    # Test all permitted
    msg = "Impersonate"
    socket = os.path.join(testdir, 'impersonate.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, False)
    rets.append(r)

    #Test self fail
    msg = "Impersonate fail self"
    socket = os.path.join(testdir, 'impersonate-proxyonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, True)
    rets.append(r)

    #Test proxy fail
    msg = "Impersonate fail proxy"
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, True)
    rets.append(r)

    #Test s4u2self half succeed
    msg = "s4u2self delegation"
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache', 's4u2self'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, False)
    rets.append(r)

    #Test proxy to self succeed
    msg = "Impersonate to self"
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, HOST_GSS,
                    path_prefix + 'impersonate.cache', 's4u2proxy'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, SVC_KTNAME, False)
    rets.append(r)

    #Test s4u2proxy half fail
    msg = "s4u2proxy fail"
    socket = os.path.join(testdir, 'impersonate-selfonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache', 's4u2proxy'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, True)
    rets.append(r)

    #Test s4u2proxy half succeed
    msg = "s4u2proxy"
    socket = os.path.join(testdir, 'impersonate-proxyonly.socket')
    cmd = " ".join(["./tests/t_impersonate", USR_NAME, HOST_GSS, PROXY_GSS,
                    path_prefix + 'impersonate.cache', 's4u2proxy'])
    r = run_cmd(testdir, env, conf, msg, socket, cmd, PROXY_KTNAME, False)
    rets.append(r)

    # Reset back gssproxy conf
    update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
    gssproxy_reload(testdir, conf['gpid'])

    e = [r for r in rets if r != 0]
    if len(e) > 0:
        return e[0]
    return 0

if __name__ == "__main__":
    from runtests import runtests_main
    runtests_main(["t_impersonate.py"])
