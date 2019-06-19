#!/usr/bin/python3
# Copyright (C) 2014,2015,2016 - GSS-Proxy contributors; see COPYING for the license.

import binascii
import glob
import os
import shutil
import signal
from string import Template
import subprocess
import sys
import time

testcase_wait = 15
cmd_index = 0

debug_all = False
debug_gssproxy = False
debug_cmd = "gdb --args"
debug_cmd_index = -1

valgrind_cmd = "valgrind", "--track-origins=yes"
valgrind_everywhere = False

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
        return "[" + key + "]"

def testlib_process_args(args):
    global debug_all, debug_cmd, debug_cmd_index, debug_gssproxy
    global testcase_wait, valgrind_cmd, valgrind_everywhere

    testcase_wait = args['timeout']
    debug_cmd_index = args['debug_num']

    debug_all = args['debug_all']
    debug_cmd = args['debug_cmd'] + " "
    debug_gssproxy = args['debug_gssproxy']

    valgrind_cmd = args['valgrind_cmd'] + " "
    valgrind_everywhere = args['force_valgrind']

def print_keyed(status, key, text, io):
    print("%s %s" % (format_key(status, key), text), file=io)

def print_success(key, text, io=sys.stderr):
    print_keyed("success", key, text, io)


def print_failure(key, text, io=sys.stderr):
    print_keyed("failure", key, text, io)


def print_warning(key, text, io=sys.stderr):
    print_keyed("other", key, text, io)

def print_return(ret, num, name, expected_failure):
    key = "PASS"
    expected = "zero" if not expected_failure else "nonzero"
    if (ret == 0 and expected_failure) or \
       (ret != 0 and not expected_failure):
       key = "FAIL"
    if (ret == 0 and not expected_failure) or \
       (ret != 0 and expected_failure):
        print_success(key, "%s test returned %s" % (name, str(ret)))
    else:
        print_failure(key, "%s test returned %s (expected %s)" %
                      (name, str(ret), expected))
        if num != -1:
            print_warning("INFO", "To debug this test case, run:\n" +
                          ("    make check CHECKARGS='--debug-num=%d'" % num))

WRAP_HOSTNAME = "kdc.gssproxy.dev"

def run_testcase_cmd(env, conf, cmd, name, expected_failure=False, wait=True):
    global testcase_wait, debug_cmd_index, cmd_index
    global valgrind_everywhere, valgrind_cmd, debug_all

    logfile = os.path.join(conf['logpath'], "test_%d.log" % cmd_index)
    logfile = open(logfile, 'w')

    print("[NAME]\n%s\n[COMMAND %d]\n%s\n[ENVIRONMENT]\n%s\n\n" % (name,
          cmd_index, cmd, env), file=logfile)
    logfile.flush()

    testenv = env.copy()

    if debug_all or debug_cmd_index == cmd_index:
        return rundebug_cmd(testenv, conf, cmd, name, expected_failure)

    run_cmd = cmd
    if valgrind_everywhere:
        run_cmd = valgrind_cmd + cmd

    p1 = subprocess.Popen(run_cmd, stderr=subprocess.STDOUT, stdout=logfile,
                          env=testenv, preexec_fn=os.setsid, shell=True,
                          executable="/bin/bash")

    if not wait:
        cmd_index += 1
        conf['prefix'] = str(cmd_index)
        return p1

    try:
        p1.wait(testcase_wait)
    except subprocess.TimeoutExpired:
        # p1.returncode is set to None here
        if not expected_failure:
            print_warning("warning", "timeout")

    logfile.close()
    print_return(p1.returncode, cmd_index, "(%d) %s" % (cmd_index, name),
                 expected_failure)
    cmd_index += 1
    conf['prefix'] = str(cmd_index)
    return p1.returncode if not expected_failure else int(not p1.returncode)

def rundebug_cmd(env, conf, cmd, name, expected_failure=False):
    global debug_cmd, cmd_index

    run_cmd = debug_cmd + cmd

    returncode = subprocess.call(run_cmd, env=env, shell=True,
                                 executable="/bin/bash")

    print_return(returncode, cmd_index, "(%d) %s" % (cmd_index, name),
                 expected_failure)
    cmd_index += 1

    return returncode if not expected_failure else int(not returncode)

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

    hosts_file = os.path.join(base, 'hosts')
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


def write_ldap_krb5_config(testdir):
    # LDAP environment config files
    ldapdir = os.path.join(testdir, "ldap")
    ldapconf = os.path.join(ldapdir, "slapd.conf")
    ldif = os.path.join(ldapdir, "k5.ldif")
    testlog = os.path.join(testdir, "ldap.log")
    stashfile = os.path.join(testdir, "ldap_passwd")

    # Kerberos environment config files
    testlog = os.path.join(testdir, 'kkrb5kdc.log')
    krb5conf = os.path.join(testdir, 'krb5.conf')
    kdcconf = os.path.join(testdir, 'kdc.conf')
    kdcdir = os.path.join(testdir, 'kdc')
    kdcstash = os.path.join(kdcdir, KDC_STASH)
    kdcdb = os.path.join(kdcdir, KDC_DBNAME)

    # Create directories for config files
    if os.path.exists(ldapdir):
        shutil.rmtree(ldapdir)
    os.makedirs(ldapdir)

    if os.path.exists(kdcdir):
        shutil.rmtree(kdcdir)
    os.makedirs(kdcdir)

    # Template LDAP config files
    # Different distros do LDAP naming differently
    schemadir = None
    for path in ["/etc/openldap/schema", "/etc/ldap/schema"]:
        if os.path.exists(path):
            schemadir = path
            break
    if schemadir == None:
        raise ValueError("Did not find LDAP schemas; is openldap installed?")

    k5schema = None
    for path in ["/usr/share/doc/krb5-server-ldap*/kerberos.schema",
                 "/usr/share/kerberos/ldap/kerberos.schema",
                 "/usr/share/doc/krb5-kdc-ldap/kerberos.schema.gz"]:
        pathlist = glob.glob(path)
        if len(pathlist) > 0:
            k5schema = pathlist[0]
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

    # Template Kerberos config files
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



def setup_ldap(testdir, wrapenv):
    write_ldap_krb5_config(testdir)

    # Set LDAP environment paths
    ldapdir = os.path.join(testdir, "ldap")
    ldapconf = os.path.join(ldapdir, "slapd.conf")
    ldif = os.path.join(ldapdir, "k5.ldif")
    testlog = os.path.join(testdir, "ldap.log")
    stashfile = os.path.join(testdir, "ldap_passwd")
    krb5conf = os.path.join(testdir, 'krb5.conf')

    ldapenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin:/usr/lib/mit/sbin',
               'KRB5_CONFIG': krb5conf}
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

def setup_kdc(testdir, wrapenv):
    # Set Kerberos environtment paths
    testlog = os.path.join(testdir, 'kkrb5kdc.log')
    krb5conf = os.path.join(testdir, 'krb5.conf')
    kdcconf = os.path.join(testdir, 'kdc.conf')
    kdcdir = os.path.join(testdir, 'kdc')
    kdcstash = os.path.join(kdcdir, KDC_STASH)
    kdcdb = os.path.join(kdcdir, KDC_DBNAME)

    kdcenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin:/usr/lib/mit/sbin',
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
HOST_SVC = "host/%s" % WRAP_HOSTNAME
HOST_GSS = "host@%s" % WRAP_HOSTNAME
PROXY_SVC = "proxy/%s" % WRAP_HOSTNAME
PROXY_GSS = "proxy@%s" % WRAP_HOSTNAME
PROXY_KTNAME = "proxy.keytab"

PROXY_LDIF_TEMPLATE = """
dn: krbPrincipalName=${HOST_SVC}@${TESTREALM},cn=${TESTREALM},cn=${KRB5_CN},${LDAP_REALM}
changetype: modify
add: krbAllowedToDelegateTo
krbAllowedToDelegateTo: ${PROXY_SVC}@${TESTREALM}
-
"""

def authorize_to_proxy(testdir, env):
    testlog = os.path.join(testdir, 'kerbsetup.log')

    t = Template(PROXY_LDIF_TEMPLATE)
    text = t.substitute({"HOST_SVC": HOST_SVC,
                         "PROXY_SVC": PROXY_SVC,
                         "TESTREALM": TESTREALM,
                         "LDAP_REALM": LDAP_REALM,
                         "KRB5_CN": KRB5_CN})
    ldif = os.path.join(testdir, "ldap", "k5proxy.ldif")
    with open(ldif, "w+") as f:
        f.write(text)

    with open(testlog, "a") as logfile:
        lmod = subprocess.Popen(["ldapmodify", "-w", LDAP_PW, "-H",
                                 "ldap://%s" % WRAP_HOSTNAME, "-D",
                                 "%s,%s" % (KRB5_USER, LDAP_REALM),
                                 "-f", ldif],
                                 stdout=logfile, stderr=logfile, env=env,
                                 preexec_fn=os.setsid)

    lmod.wait()
    if lmod.returncode != 0:
        raise ValueError("Proxy princ setup failed")

def setup_keys(testdir, env):

    testlog = os.path.join(testdir, 'kerbsetup.log')

    svc_name = "host/%s" % WRAP_HOSTNAME
    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    cmd = "addprinc -randkey -e %s +ok_to_auth_as_delegate %s" % (KEY_TYPE,
                                                                  svc_name)
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

    proxy_keytab = os.path.join(testdir, PROXY_KTNAME)
    cmd = "addprinc -randkey -e %s -requires_preauth %s" % (KEY_TYPE,
                                                            PROXY_SVC)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)
    shutil.copy(svc_keytab, proxy_keytab)
    cmd = "ktadd -k %s -e %s %s" % (proxy_keytab, KEY_TYPE, PROXY_SVC)
    with (open(testlog, 'a')) as logfile:
        kadmin_local(cmd, env, logfile)

    authorize_to_proxy(testdir, env)

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




GSSPROXY_CONF_TEMPLATE = '''
[gssproxy]
  debug_level = 3

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = ${UIDNUMBER}
  allow_client_ccache_sync = yes

[service/badkeytab]
  mechs = krb5
  cred_store = keytab:/intentionally/missing/keytab
  euid = 123
'''

# Contains a garbage service entry
GSSPROXY_CONF_MINIMAL_TEMPLATE = '''
[gssproxy]
  debug_level = 3

[service/dontuse]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = nobody
  allow_client_ccache_sync = yes
'''

GSSPROXY_CONF_SOCKET_TEMPLATE = '''
[gssproxy]
  debug_level = 3

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  cred_store = client_keytab:${GSSPROXY_CLIENT_KEYTAB}
  trusted = yes
  euid = ${UIDNUMBER}
  socket = ${SECOND_SOCKET}
  allow_client_ccache_sync = yes
'''

GSSPROXY_MULTI_TEMPLATE = '''
[gssproxy]
  debug_level = 2

[service/test]
  mechs = krb5
  cred_store = keytab:${GSSPROXY_KEYTAB}
  krb5_principal = ${GSSPROXY_CLIENT_PRINCIPAL}
  trusted = yes
  euid = ${UIDNUMBER}
  allow_client_ccache_sync = yes
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
            'SECOND_SOCKET': socket2,
            'PROGDIR': os.path.join(os.getcwd(), "tests"),
            'TESTDIR': testdir}
    if 'client_name' in env:
        subs['GSSPROXY_CLIENT_PRINCIPAL'] = env['client_name']
    text = t.substitute(subs)
    with open(conf, 'w+') as f:
        f.write(text)

def setup_gssproxy(testdir, logfile, env):
    global debug_gssproxy, valgrind_cmd

    gssproxy = os.path.join(testdir, 'gssproxy')
    if os.path.exists(gssproxy):
        shutil.rmtree(gssproxy)
    os.makedirs(gssproxy)

    update_gssproxy_conf(testdir, env, GSSPROXY_CONF_TEMPLATE)

    gpenv = env.copy()
    gpenv['KRB5_TRACE'] = os.path.join(testdir, 'gp_krb5_trace.log')

    socket = os.path.join(gssproxy, 'gp.sock')
    conf = os.path.join(gssproxy, 'gp.conf')

    cmd = "./gssproxy -i -s " + socket + " -c " + conf

    full_command = valgrind_cmd + cmd

    if debug_gssproxy:
        full_command = cmd

    gproc = subprocess.Popen(full_command,
                             stdout=logfile, stderr=logfile,
                             env=gpenv, preexec_fn=os.setsid, shell=True,
                             executable="/bin/bash")

    if debug_gssproxy:
        print("PID: %d" % (gproc.pid))
        print("Attach and start debugging, then press enter to continue.")
        input()

    return gproc, socket
