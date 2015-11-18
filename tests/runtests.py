#!/usr/bin/python3
# copyright (C) 2014.2015 - GSS-Proxy contributors, see COPYING for the license.

import argparse
import binascii
import glob
import os
import shutil
import signal
from string import Template
import subprocess
import sys
import time

try:
    from colorama import Fore, Style

    def format_key(status, key):
        if status == "success":
            color = Fore.GREEN
        elif status == "failure":
            color = Fore.RED
        else:
            color = Style.DIM + Fore.YELLOW
        return "[" + color + key + Style.RESET_ALL + "]"

except ImportError:

    def format_key(status, key):
        if status == "success":
            color = " OO "
        elif status == "failure":
            color = " XX "
        else:
            color = " -- "
        return "[" + color + key + color + "]"

def print_keyed(status, key, text, io):
    print("%s %s" % (format_key(status, key), text), file=io)


def print_success(key, text, io=sys.stderr):
    print_keyed("success", key, text, io)


def print_failure(key, text, io=sys.stderr):
    print_keyed("failure", key, text, io)


def print_warning(key, text, io=sys.stderr):
    print_keyed("other", key, text, io)


def parse_args():
    parser = argparse.ArgumentParser(description='GSS-Proxy Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")

    return vars(parser.parse_args())


WRAP_HOSTNAME = "kdc.gssproxy.dev"


def setup_wrappers(base):

    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'socket_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        raise ValueError('Socket Wrappers not available')

    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'nss_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        raise ValueError('Socket Wrappers not available')

    wrapdir = os.path.join(base, 'wrapdir')
    if not os.path.exists(wrapdir):
        os.makedirs(wrapdir)

    hosts_file = os.path.join(testdir, 'hosts')
    with open(hosts_file, 'w+') as f:
        f.write('127.0.0.9 %s' % WRAP_HOSTNAME)

    wenv = {'LD_PRELOAD': 'libsocket_wrapper.so libnss_wrapper.so',
            'SOCKET_WRAPPER_DIR': wrapdir,
            'SOCKET_WRAPPER_DEFAULT_IFACE': '9',
            'NSS_WRAPPER_HOSTNAME': WRAP_HOSTNAME,
            'NSS_WRAPPER_HOSTS': hosts_file}

    return wenv


TESTREALM = "GSSPROXY.DEV"
KDC_DBNAME = 'db.file'
KDC_STASH = 'stash.file'
KDC_PASSWORD = 'gssproxy'
KRB5_CONF_TEMPLATE = '''
[libdefaults]
  default_realm = ${TESTREALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  ticket_lifetime = 24h
  forwardable = yes
  default_ccache_name = FILE://${TESTDIR}/ccaches/krb5_ccache_XXXXXX

[realms]
  ${TESTREALM} = {
    kdc =${WRAP_HOSTNAME}
  }

[domain_realm]
  .gssproxy.dev = GSSPROXY.DEV
  gssproxy.dev = GSSPROXY.DEV

[dbmodules]
  ${TESTREALM} = {
    database_name = ${KDCDIR}/${KDC_DBNAME}
  }
'''
KDC_CONF_TEMPLATE = '''
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88
 restrict_anonymous_to_tgt = true

[realms]
 ${TESTREALM} = {
  master_key_type = aes256-cts
  max_life = 7d
  max_renewable_life = 14d
  acl_file = ${KDCDIR}/kadm5.acl
  dict_file = /usr/share/dict/words
  default_principal_flags = +preauth
  admin_keytab = ${TESTREALM}/kadm5.keytab
  key_stash_file = ${KDCDIR}/${KDC_STASH}
 }
[logging]
  kdc = FILE:${KDCLOG}
'''


def setup_kdc(testdir, wrapenv):

    # setup kerberos environment
    testlog = os.path.join(testdir, 'kkrb5kdc.log')
    krb5conf = os.path.join(testdir, 'krb5.conf')
    kdcconf = os.path.join(testdir, 'kdc.conf')
    kdcdir = os.path.join(testdir, 'kdc')
    kdcstash = os.path.join(kdcdir, KDC_STASH)
    kdcdb = os.path.join(kdcdir, KDC_DBNAME)
    if os.path.exists(kdcdir):
        shutil.rmtree(kdcdir)
    os.makedirs(kdcdir)

    t = Template(KRB5_CONF_TEMPLATE)
    text = t.substitute({'TESTREALM': TESTREALM,
                         'TESTDIR': testdir,
                         'KDCDIR': kdcdir,
                         'KDC_DBNAME': KDC_DBNAME,
                         'WRAP_HOSTNAME': WRAP_HOSTNAME})
    with open(krb5conf, 'w+') as f:
        f.write(text)

    t = Template(KDC_CONF_TEMPLATE)
    text = t.substitute({'TESTREALM': TESTREALM,
                         'KDCDIR': kdcdir,
                         'KDCLOG': testlog,
                         'KDC_STASH': KDC_STASH})
    with open(kdcconf, 'w+') as f:
        f.write(text)

    kdcenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin',
              'KRB5_CONFIG': krb5conf,
              'KRB5_KDC_PROFILE': kdcconf}
    kdcenv.update(wrapenv)

    with (open(testlog, 'a')) as logfile:
        ksetup = subprocess.Popen(["kdb5_util", "create", "-s",
                                   "-r", TESTREALM, "-P", KDC_PASSWORD],
                                  stdout=logfile, stderr=logfile,
                                  env=kdcenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('KDC Setup failed')

    kdcproc = subprocess.Popen(['krb5kdc', '-n'],
                               env=kdcenv, preexec_fn=os.setsid)

    return kdcproc, kdcenv


def kadmin_local(cmd, env, logfile):
    ksetup = subprocess.Popen(["kadmin.local", "-q", cmd],
                              stdout=logfile, stderr=logfile,
                              env=env, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('Kadmin local [%s] failed' % cmd)


USR_NAME = "user"
USR_KTNAME = "user.gssproxy.keytab"
USR_CCACHE = "krb5ccache_usr"
SVC_KTNAME = "kdc.gssproxy.keytab"
KEY_TYPE = "aes256-cts-hmac-sha1-96:normal"
USR2_NAME = "user2"
USR2_PWD = "usrpwd"

def setup_keys(tesdir, env):

    testlog = os.path.join(testdir, 'kerbsetup.log')

    svc_name = "host/%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, svc_name)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)
    cmd = "ktadd -k %s -e %s %s" % (svc_keytab, KEY_TYPE, svc_name)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

    usr_keytab = os.path.join(testdir, USR_KTNAME)
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, USR_NAME)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)
    cmd = "ktadd -k %s -e %s %s" % (usr_keytab, KEY_TYPE, USR_NAME)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

    cmd = "addprinc -pw %s %s" % (USR2_PWD, USR2_NAME)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

    keys_env = { "KRB5_KTNAME": svc_keytab}
    keys_env.update(env)

    return keys_env


# This is relative to the path where the test binary is being run
GSSAPI_SYMLINK_DIR = ".test655"
MECH_CONF_TEMPLATE = '''
gssproxy_v1		2.16.840.1.113730.3.8.15.1	${PROXYMECH}		<interposer>
'''


def setup_gssapi_env(testdir, wrapenv):

    libgssapi_dir = os.path.join(testdir, 'libgssapi')
    libgssapi_mechd_dir = os.path.join(GSSAPI_SYMLINK_DIR, 'mech.d')

    if os.path.exists(libgssapi_dir):
        shutil.rmtree(libgssapi_dir)
    os.makedirs(libgssapi_dir)

    if os.path.lexists(GSSAPI_SYMLINK_DIR):
        os.unlink(GSSAPI_SYMLINK_DIR)
    os.symlink(libgssapi_dir, GSSAPI_SYMLINK_DIR)
    os.makedirs(libgssapi_mechd_dir)

    lib = None
    try:
        libs = subprocess.check_output(
            ['pkg-config', '--libs-only-L', 'krb5-gssapi']).decode("utf-8")
    except:
        raise ValueError('libgssapi not available')

    # find them all and get the longest name in the hopes
    # we hit /usr/lib64/libgssapi_krb5.so.2.2 in preference
    if libs is not None and libs.startswith("-L"):
        libs = glob.glob(libs[2:].strip() + "/libgssapi*.so*")
    else:
        libs = glob.glob("/usr/lib*/libgssapi*.so*")

    lib_len = 0
    for l in libs:
        if len(l) > lib_len:
            lib_len = len(l)
            lib = l
    if not lib:
        raise KeyError('Gssapi library not found')

    libgssapi_lib = os.path.join(libgssapi_dir, os.path.basename(lib))
    libgssapi_conf = os.path.join(libgssapi_mechd_dir, 'gssproxy-mech.conf')

    # horrible, horrible hack to load our own configuration later
    with open(lib, 'rb') as f:
        data = binascii.hexlify(f.read())
    with open(libgssapi_lib, 'wb') as f:
        data = data.replace(binascii.hexlify(b'/etc/gss/mech.d'),
                            binascii.hexlify(
                                libgssapi_mechd_dir.encode("utf-8")))
        f.write(binascii.unhexlify(data))

    shutil.copy('.libs/proxymech.so', libgssapi_dir)
    proxymech = os.path.join(libgssapi_dir, 'proxymech.so')

    t = Template(MECH_CONF_TEMPLATE)
    text = t.substitute({'PROXYMECH': proxymech})
    with open(libgssapi_conf, 'w+') as f:
        f.write(text)

    # first swallow in wrapenv vars if any
    gssapi_env = dict()
    gssapi_env.update(wrapenv)

    # then augment preload if any
    ld_pre = ''
    if 'LD_PRELOAD' in wrapenv:
        ld_pre = wrapenv['LD_PRELOAD'] + ' '
    ld_pre = ld_pre + os.path.join(GSSAPI_SYMLINK_DIR,
                                   os.path.basename(libgssapi_lib))
    gssapi_env['LD_PRELOAD'] = ld_pre

    return gssapi_env


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


GSSPROXY_CONF_TEMPLATE = '''
[gssproxy]
  debug_level = 2

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = ccache:FILE:${GSSPROXY_CLIENT_CCACHE}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = ${UIDNUMBER}
'''

# Contains a garbage service entry
GSSPROXY_CONF_MINIMAL_TEMPLATE = '''
[gssproxy]

[service/dontuse]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = ccache:FILE:${GSSPROXY_CLIENT_CCACHE}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = nobody
'''

GSSPROXY_CONF_SOCKET_TEMPLATE = GSSPROXY_CONF_TEMPLATE + '''
  socket = ${SECOND_SOCKET}
'''

def update_gssproxy_conf(testdir, env, template):
    gssproxy = os.path.join(testdir, 'gssproxy')
    ccache = os.path.join(gssproxy, 'gpccache')
    ckeytab = os.path.join(testdir, USR_KTNAME)
    conf = os.path.join(gssproxy, 'gp.conf')
    socket2 = os.path.join(gssproxy, 'gp.sock2')

    t = Template(template)
    text = t.substitute({'GSSPROXY_KEYTAB': env['KRB5_KTNAME'],
                         'GSSPROXY_CLIENT_CCACHE': ccache,
                         'GSSPROXY_CLIENT_KEYTAB': ckeytab,
                         'UIDNUMBER': os.getuid(),
                         'SECOND_SOCKET': socket2})
    with open(conf, 'w+') as f:
        f.write(text)

def setup_gssproxy(testdir, logfile, env):

    gssproxy = os.path.join(testdir, 'gssproxy')
    if os.path.exists(gssproxy):
        shutil.rmtree(gssproxy)
    os.makedirs(gssproxy)

    update_gssproxy_conf(testdir, env, GSSPROXY_CONF_TEMPLATE)

    socket = os.path.join(gssproxy, 'gp.sock')
    conf = os.path.join(gssproxy, 'gp.conf')
    gproc = subprocess.Popen(["./gssproxy", "-i", "-d",
                              "-s", socket, "-c", conf],
                             stdout=logfile, stderr=logfile,
                             env=env, preexec_fn=os.setsid)

    return gproc, socket


def run_basic_test(testdir, env, expected_failure=False):

    logfile = open(os.path.join(testdir, 't_init_accept.log'), 'a')

    svc_name = "host@%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    svcenv = {'KRB5_KTNAME': svc_keytab,
              'KRB5CCNAME': os.path.join(testdir, 't_accept.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't_accept.trace')}
    svcenv.update(env)

    clienv = {'KRB5CCNAME': os.path.join(testdir, 't_init.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't_init.trace'),
              'GSS_USE_PROXY': 'yes',
              'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    clienv.update(env)

    pipe0 = os.pipe()
    pipe1 = os.pipe()

    p1 = subprocess.Popen(["./tests/t_init", svc_name],
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


def run_acquire_test(testdir, env, expected_failure=False):

    logfile = open(os.path.join(testdir, 't_acquire.log'), 'a')

    svc_name = "host@%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    testenv = {'KRB5CCNAME': os.path.join(testdir, 't_acquire.ccache'),
               'KRB5_KTNAME': svc_keytab,
               'KRB5_TRACE': os.path.join(testdir, 't_acquire.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_acquire", svc_name]
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


def run_impersonate_test(testdir, env, expected_failure=False):

    logfile = open(os.path.join(testdir, 't_impersonate.log'), 'a')

    svc_name = "host@%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    testenv = {'KRB5CCNAME': os.path.join(testdir, 't_impersonate.ccache'),
               'KRB5_KTNAME': svc_keytab,
               'KRB5_TRACE': os.path.join(testdir, 't_impersonate.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_impersonate", USR_NAME, svc_name]
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

            print("Testing basic acquire creds", file=sys.stderr)
            run_acquire_test(testdir, gssapienv)

            print("Testing impersonate creds", file=sys.stderr)
            run_impersonate_test(testdir, gssapienv)

            print("Testing basic init/accept context", file=sys.stderr)
            run_basic_test(testdir, gssapienv)

            print("Testing basic SIGHUP with no change", file=sys.stderr)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv)

            print("Testing SIGHUP with dropped service", file=sys.stderr)
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_MINIMAL_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, True)

            print("Testing SIGHUP with new service", file=sys.stderr)
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv)

            print("Testing SIGHUP with change of socket", file=sys.stderr)
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_SOCKET_TEMPLATE)
            gssapienv['GSSPROXY_SOCKET'] += "2"
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv)
    finally:
        for name in processes:
            print("Killing %s" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)
