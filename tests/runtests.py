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

KRB5_CN = "Kerberos"
KRB5_USER = "cn=root"
LDAP_DC = "gssproxy"
LDAP_REALM = "dc=" + LDAP_DC + ",dc=dev"
LDAP_PW = "root"
SLAPD_CONF_TEMPLATE = """
include   ${LDAP_KRB_SCHEMA}
include   ${SCHEMADIR}/core.schema
include   ${SCHEMADIR}/cosine.schema
include   ${SCHEMADIR}/inetorgperson.schema
include   ${SCHEMADIR}/nis.schema

allow bind_v2

pidfile   ${LDAPDIR}/slapd.pid

database  config
rootdn    ${KRB5_USER},cn=config
rootpw    ${LDAP_PW}

moduleload back_mdb
database  mdb
suffix    "${LDAP_REALM}"
rootdn    "${KRB5_USER},${LDAP_REALM}"
rootpw    ${LDAP_PW}

directory ${LDAPDIR}
logfile   ${LDAP_LOG}
"""
KERBEROS_LDIF_TEMPLATE="""
dn: ${LDAP_REALM}
objectClass: domain
dc: ${LDAP_DC}

dn: cn=${KRB5_CN},${LDAP_REALM}
objectClass: krbContainer
cn: ${KRB5_CN}
"""

def setup_ldap(testdir, wrapenv):
    # setup ldap environment
    ldapdir = os.path.join(testdir, "ldap")
    ldapconf = os.path.join(ldapdir, "slapd.conf")
    ldif = os.path.join(ldapdir, "k5.ldif")
    testlog = os.path.join(testdir, "ldap.log")
    stashfile = os.path.join(testdir, "ldap_passwd")
    if os.path.exists(ldapdir):
        shutil.rmtree(ldapdir)
    os.makedirs(ldapdir)

    # different distros do LDAP naming differently
    schemadir = None
    for path in ["/etc/openldap/schema", "/etc/ldap/schema"]:
        if os.path.exists(path):
            schemadir = path
            break
    if schemadir == None:
        raise ValueError("Did not find LDAP schemas; is openldap installed?")

    k5schema = None
    for path in ["/usr/share/doc/krb5-server-ldap/kerberos.schema",
                 "/usr/share/doc/krb5-kdc-ldap/kerberos.schema.gz"]:
        if os.path.exists(path):
            k5schema = path
            break
    if k5schema == None:
        print("Please be sure krb5 ldap packages are installed")
        raise ValueError("No LDAP kerberos.schema found")
    elif k5schema.endswith(".gz"):
        sdata = subprocess.check_output(["zcat", k5schema])
        k5schema = os.path.join(ldapdir, "kerberos.schema")
        with open(k5schema, "w") as f:
            f.write(sdata.decode("UTF-8"))

    t = Template(SLAPD_CONF_TEMPLATE)
    text = t.substitute({"LDAPDIR": ldapdir,
                         "LDAP_REALM": LDAP_REALM,
                         "LDAP_PW": LDAP_PW,
                         "LDAP_LOG": testlog,
                         "LDAP_KRB_SCHEMA": k5schema,
                         "SCHEMADIR": schemadir,
                         "KRB5_USER": KRB5_USER})
    with open(ldapconf, "w+") as f:
        f.write(text)

    t = Template(KERBEROS_LDIF_TEMPLATE)
    text = t.substitute({"LDAP_REALM": LDAP_REALM,
                         "LDAP_DC": LDAP_DC,
                         "KRB5_CN": KRB5_CN})
    with open(ldif, "w+") as f:
        f.write(text)

    ldapenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin'}
    ldapenv.update(wrapenv)

    with open(testlog, "a") as logfile:
        lsetup = subprocess.Popen(["slapadd", "-f", ldapconf, "-l", ldif],
                                  stdout=logfile, stderr=logfile,
                                  env=ldapenv, preexec_fn=os.setsid)
    lsetup.wait()
    if lsetup.returncode != 0:
        raise ValueError("LDAP Setup failed")

    with open(testlog, "a") as logfile:
        ldapproc = subprocess.Popen(["slapd", "-d", "0", "-f", ldapconf,
                                     "-h", "ldap://%s" % WRAP_HOSTNAME],
                                    env=ldapenv, preexec_fn=os.setsid)

    print("Waiting for LDAP server to start...")
    time.sleep(5)

    with open(testlog, "a") as logfile:
        ssetup = subprocess.Popen(["kdb5_ldap_util", "stashsrvpw", "-w",
                                   LDAP_PW, "-H", "ldap://%s" % WRAP_HOSTNAME,
                                   "-f", stashfile,
                                   "%s,%s" % (KRB5_USER, LDAP_REALM)],
                                  stdin=subprocess.PIPE, stdout=logfile,
                                  stderr=logfile, env=ldapenv,
                                  preexec_fn=os.setsid)
    ssetup.communicate((LDAP_PW + '\n' + LDAP_PW + '\n').encode("UTF-8"))
    if ssetup.returncode != 0:
        os.killpg(ldapproc.pid, signal.SIGTERM)
        raise ValueError("stashsrvpw failed")

    return ldapproc, ldapenv

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
    kdc = ${WRAP_HOSTNAME}
    admin_server = ${WRAP_HOSTNAME}
  }

[domain_realm]
  .gssproxy.dev = GSSPROXY.DEV
  gssproxy.dev = GSSPROXY.DEV

[dbmodules]
  ${TESTREALM} = {
    db_library = kldap
    ldap_kerberos_container_dn = cn=${KRB5_CN},${LDAP_REALM}
    ldap_kdc_dn = ${KRB5_USER},${LDAP_REALM}
    ldap_kadmind_dn = ${KRB5_USER},${LDAP_REALM}
    ldap_service_password_file = ${TESTDIR}/ldap_passwd
    ldap_servers = ldap://${WRAP_HOSTNAME}
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
                         'KRB5_CN': KRB5_CN,
                         'KRB5_USER': KRB5_USER,
                         'KDC_DBNAME': KDC_DBNAME,
                         'LDAP_REALM': LDAP_REALM,
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
        ksetup = subprocess.Popen(["kdb5_ldap_util", "-H",
                                   "ldap://%s" % WRAP_HOSTNAME, "-D",
                                   "%s,%s" % (KRB5_USER, LDAP_REALM),
                                   "create", "-w", LDAP_PW, "-P", KDC_PASSWORD,
                                   "-s", "-r", TESTREALM],
                                  stdout=logfile, stderr=logfile,
                                  env=kdcenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('KDC Setup failed')

    kdcproc = subprocess.Popen(['krb5kdc', '-n'],
                               env=kdcenv, preexec_fn=os.setsid)
    time.sleep(5)
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
MULTI_KTNAME = "multi.gssproxy.keytab"
MULTI_UPN = "multi$"
MULTI_SVC = "multi/%s" % WRAP_HOSTNAME

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

    keys_env = {"client_keytab": usr_keytab,
                "KRB5_KTNAME": svc_keytab}
    keys_env.update(env)

    return keys_env

def setup_multi_keys(testdir, env):

    testlog = os.path.join(testdir, 'kerbsetup.log')
    keytab = os.path.join(testdir, MULTI_KTNAME)

    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, MULTI_SVC)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)
    cmd = "ktadd -k %s -e %s %s" % (keytab, KEY_TYPE, MULTI_SVC)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

    # add a second key using the UPN
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, MULTI_UPN)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)
    cmd = "ktadd -k %s -e %s %s" % (keytab, KEY_TYPE, MULTI_UPN)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

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

GSSPROXY_MULTI_TEMPLATE = '''
[gssproxy]
  debug_level = 2

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = ccache:FILE:${GSSPROXY_CLIENT_CCACHE}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  krb5_principal = ${GSSPROXY_CLIENT_PRINCIPAL}
  trusted = yes
  euid = ${UIDNUMBER}
'''

def update_gssproxy_conf(testdir, env, template):
    gssproxy = os.path.join(testdir, 'gssproxy')
    ccache = os.path.join(gssproxy, 'gpccache')
    ckeytab = env['client_keytab']
    conf = os.path.join(gssproxy, 'gp.conf')
    socket2 = os.path.join(gssproxy, 'gp.sock2')

    t = Template(template)
    subs = {'GSSPROXY_KEYTAB': env['KRB5_KTNAME'],
            'GSSPROXY_CLIENT_CCACHE': ccache,
            'GSSPROXY_CLIENT_KEYTAB': ckeytab,
            'UIDNUMBER': os.getuid(),
            'SECOND_SOCKET': socket2}
    if 'client_name' in env:
        subs['GSSPROXY_CLIENT_PRINCIPAL'] = env['client_name']
    text = t.substitute(subs)
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
    gproc = subprocess.Popen(["valgrind", "--track-origins=yes",
                              "./gssproxy", "-i", "-d",
                              "-s", socket, "-c", conf],
                             stdout=logfile, stderr=logfile,
                             env=env, preexec_fn=os.setsid)

    return gproc, socket


def run_basic_test(testdir, env, conf, expected_failure=False):

    logfile = conf['logfile']

    svcenv = {'KRB5_KTNAME': conf['keytab'],
              'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_accept.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_accept.trace')}
    svcenv.update(env)

    client_name = conf.get('client_name', None)
    if client_name is not None:
        init_cmd = ["./tests/t_init", conf['svc_name'], client_name]
    else:
        init_cmd = ["./tests/t_init", conf['svc_name']]

    clienv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.ccache'),
              'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                  '_init.trace'),
              'GSS_USE_PROXY': 'yes',
              'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    clienv.update(env)

    print("[SVCENV]\n%s\n[CLIENV]\n%s\nCLI NAME: %s\n" % (
          svcenv, clienv, client_name), file=logfile)

    pipe0 = os.pipe()
    pipe1 = os.pipe()

    p1 = subprocess.Popen(init_cmd,
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


def run_acquire_test(testdir, env, conf, expected_failure=False):

    logfile = conf['logfile']

    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_acquire.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_acquire", conf['svc_name']]
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


def run_impersonate_test(testdir, env, conf, expected_failure=False):

    logfile = conf['logfile']

    testenv = {'KRB5CCNAME': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.ccache'),
               'KRB5_KTNAME': conf['keytab'],
               'KRB5_TRACE': os.path.join(testdir, 't' + conf['prefix'] +
                                                   '_impersonate.trace'),
               'GSS_USE_PROXY': 'yes',
               'GSSPROXY_BEHAVIOR': 'REMOTE_FIRST'}
    testenv.update(env)

    cmd = ["./tests/t_impersonate", USR_NAME, conf['svc_name']]
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

        ldapproc, ldapenv = setup_ldap(testdir, wrapenv)
        processes["LDAP(%d)" % ldapproc.pid] = ldapproc

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

            basicconf = {'svc_name': "host@%s" % WRAP_HOSTNAME,
                         'keytab': os.path.join(testdir, SVC_KTNAME)}

            # Test 01
            testnum = 1
            print("Testing basic acquire creds", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir,
                                  '%02d_basic_acquire.log' % testnum), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_acquire_test(testdir, gssapienv, basicconf)

            # Test 02
            testnum += 1
            print("Testing impersonate creds", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir, '02_impersonate.log'), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_impersonate_test(testdir, gssapienv, basicconf)

            # Test 03
            testnum += 1
            print("Testing basic init/accept context", file=sys.stderr)
            basicconf['logfile'] = \
                open(os.path.join(testdir, '03_basic_exchange.log'), 'a')
            basicconf['prefix'] = '%02d' % testnum
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 1)
            testnum += 1
            basicconf['logfile'] = \
                open(os.path.join(testdir, '04_sighups.log'), 'a')

            print("Testing basic SIGHUP with no change", file=sys.stderr)
            basicconf['prefix'] = '%02d_1' % testnum
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 2)
            print("Testing SIGHUP with dropped service", file=sys.stderr)
            basicconf['prefix'] = '%02d_2' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_MINIMAL_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf, True)

            # Test 04 (part 3)
            print("Testing SIGHUP with new service", file=sys.stderr)
            basicconf['prefix'] = '%02d_3' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 4)
            print("Testing SIGHUP with change of socket", file=sys.stderr)
            basicconf['prefix'] = '%02d_4' % testnum
            update_gssproxy_conf(testdir, keysenv, GSSPROXY_CONF_SOCKET_TEMPLATE)
            gssapienv['GSSPROXY_SOCKET'] += "2"
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 05 (part 1)
            testnum += 1
            basicconf['logfile'] = \
                open(os.path.join(testdir, '05_multiple-keys.log'), 'a')
            setup_multi_keys(testdir, gssapienv)
            gssapienv['GSSPROXY_SOCKET'] = gpsocket

            # Q: What are we testing here ?
            # A: A client calling gss_init_sec_context() w/o explicitly
            # acquiring credentials before hand. [Note: in this case
            # gssproxy uses the 'keytab' specified in the store and ignores
            # the 'client_keytab' one].
            # A gssproxy configruation where the keytab containes multiple
            # keys, and a krb5_principal option that sepcify what name we
            # want to use.
            # We try both names to make sure we target a specific key and not
            # just pick up the first in the keytab (which is the normal
            # behavior).

            print("Testing multiple keys Keytab with first principal",
                  file=sys.stderr)
            if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
                os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
            basicconf['prefix'] = '%02d_1' % testnum
            p1env = {}
            p1env.update(keysenv)
            p1env['client_name'] = MULTI_UPN
            p1env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
            update_gssproxy_conf(testdir, p1env, GSSPROXY_MULTI_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)

            # Test 04 (part 2)
            print("Testing multiple keys Keytab with second principal",
                  file=sys.stderr)
            if os.path.exists(os.path.join(testdir, 'gssproxy', 'gpccache')):
                os.unlink(os.path.join(testdir, 'gssproxy', 'gpccache'))
            basicconf['prefix'] = '%02d_2' % testnum
            p2env = {}
            p2env.update(keysenv)
            p2env['client_name'] = MULTI_SVC
            p2env['KRB5_KTNAME'] = os.path.join(testdir, MULTI_KTNAME)
            update_gssproxy_conf(testdir, p2env, GSSPROXY_MULTI_TEMPLATE)
            os.kill(gproc.pid, signal.SIGHUP)
            time.sleep(1) #Let gssproxy reload everything
            run_basic_test(testdir, gssapienv, basicconf)
    finally:
        for name in processes:
            print("Killing %s" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)
