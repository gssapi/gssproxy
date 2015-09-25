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


def parse_args():
    parser = argparse.ArgumentParser(description='GSS-Proxy Tests Environment')
    parser.add_argument('--path', default='%s/scratchdir' % os.getcwd(),
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
    testlog = os.path.join(testdir, 'kerb.log')
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


def setup_keys(tesdir, env):

    testlog = os.path.join(testdir, 'kerb.log')

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

    if os.path.exists(GSSAPI_SYMLINK_DIR):
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
    testlog = os.path.join(testdir, 'tests.log')

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

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = ccache:FILE:${GSSPROXY_CLIENT_CCACHE}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = ${UIDNUMBER}
'''


def setup_gssproxy(testdir, logfile, env):

    gssproxy = os.path.join(testdir, 'gssproxy')
    if os.path.exists(gssproxy):
        shutil.rmtree(gssproxy)
    os.makedirs(gssproxy)

    socket = os.path.join(gssproxy, 'gp.sock')
    ccache = os.path.join(gssproxy, 'gpccache')
    ckeytab = os.path.join(testdir, USR_KTNAME)

    conf = os.path.join(gssproxy, 'gp.conf')
    t = Template(GSSPROXY_CONF_TEMPLATE)
    text = t.substitute({'GSSPROXY_KEYTAB': env['KRB5_KTNAME'],
                         'GSSPROXY_CLIENT_CCACHE': ccache,
                         'GSSPROXY_CLIENT_KEYTAB': ckeytab,
                         'UIDNUMBER': os.getuid()})
    with open(conf, 'w+') as f:
        f.write(text)

    gproc = subprocess.Popen(["./gssproxy", "-i", "-d",
                              "-s", socket, "-c", conf],
                             stdout=logfile, stderr=logfile,
                             env=env, preexec_fn=os.setsid)

    return gproc, socket


def run_basic_test(testdir, logfile, env):

    print("STARTING BASIC init/Accept tests")

    svc_name = "host@%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    svcenv = {'KRB5_KTNAME': svc_keytab}
    svcenv.update(env)

    cli_keytab = os.path.join(testdir, USR_KTNAME)
    cli_ccache = os.path.join(testdir, 't_basic_ccname')
    clienv = {'GSS_USE_PROXY': 'yes',
              'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
              #'KRB5CCNAME': cli_ccache,
              #'KRB5_CLIENT_KTNAME': cli_keytab}
    clienv.update(env)

    pipe0 = os.pipe()
    pipe1 = os.pipe()

    p1 = subprocess.Popen(["./tests/t_init", svc_name],
                          stdin=pipe0[0], stdout=pipe1[1],
                          stderr=logfile, env=clienv, preexec_fn=os.setsid)
    p2 = subprocess.Popen(["./tests/t_accept"],
                          stdin=pipe1[0], stdout=pipe0[1],
                          stderr=logfile, env=svcenv, preexec_fn=os.setsid)

    p1.wait()
    if p1.returncode != 0:
        print("FAILED: Init test", file=sys.stderr)
        try:
            os.killpg(p2.pid, signal.SIGTERM)
        except OSError:
            pass
    else:
        print("SUCCESS: Init test", file=sys.stderr)
    p2.wait()
    if p2.returncode != 0:
        print("FAILED: Accept test", file=sys.stderr)
        try:
            os.killpg(p1.pid, signal.SIGTERM)
        except OSError:
            pass
    else:
        print("SUCCESS: Accept test", file=sys.stderr)


if __name__ == '__main__':

    args = parse_args()

    testdir = args['path']
    if os.path.exists(testdir):
        shutil.rmtree(testdir)
    os.makedirs(testdir)

    processes = dict()

    testlog = os.path.join(testdir, 'tests.log')

    try:
        wrapenv = setup_wrappers(testdir)

        kdcproc, kdcenv = setup_kdc(testdir, wrapenv)
        processes['KDC(%d)' % kdcproc.pid] = kdcproc

        keysenv = setup_keys(testdir, kdcenv)

        gssapienv = setup_gssapi_env(testdir, kdcenv)

        run_interposetest(testdir, gssapienv)

        with (open(testlog, 'a')) as logfile:
            gproc, gpsocket = setup_gssproxy(testdir, logfile, keysenv)
            time.sleep(2) #Give time to gssproxy to fully start up
            processes['GSS-Proxy(%d)' % gproc.pid] = gproc
            gssapienv['GSSPROXY_SOCKET'] = gpsocket
            run_basic_test(testdir, logfile, gssapienv)

    finally:
        for name in processes:
            print("Killing %s" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)
