# Getting started with gssproxy

In this folder is detailed documentation on how gssproxy works internally
(Behavior, ProtocolDocumentation) as well as configuration walkthroughs for
specific services (Apache, NFS) and information on our releases
(ReleaseProcess, Releases).

This document attempts to cover how to use gssproxy with any simple,
well-behaved service, and explain in broad strokes what each step
accomplishes.  All commands should be run as root.

## Background

The GSSAPI (Generic Security Services API) is a RFC-standardized interface for
applications that wish to use security libraries.  Most commonly, GSSAPI is
used as an interface to Kerberos, though there are other mechanisms provided
as well (e.g., SPNEGO for Single-Sign On on the web; see the Apache docs in
this folder for more information on that).

When an application uses GSSAPI, typically it will have direct access to its
security credentials, and all cryptographic operations are performed in the
application's process.  This is undesirable, but fortunately gssproxy can help
in almost all use cases!  gssproxy provides privilege separation to
applications using the GSSAPI: the gssproxy daemon runs on the system, holds
the application's credentials, and performs operations on behalf of the
application.

This is completely transparent to the application.  However, some
configuration is required, which we'll now go through.

## Configuring gssproxy

(For a detailed explanation of any of the options described in this section,
see the man page for gssproxy.conf (`man 5 gssproxy.conf`).)

gssproxy configuration typically lives in **/etc/gssproxy**.  On most systems,
this directory will already contain a couple files, which can usually be
ignored (but will be explained briefly anyway).

- **gssproxy.conf** is the main gssproxy configuration file: options affecting
  operation of the daemon itself live here (e.g., logging levels).
  
- **##-servicename.conf** are the service configuration files (where "##" is a
  two-digit number; the files are loaded in numeric order by gssproxy).
  
We will be making one of the latter file for your application.  Pick a useful
name for your service - it will be used in log files.

gssproxy configuration snippets are INI-style, so start with a service header:
`[service/my_app]`.

Then set the mechanisms we wish to allow: `mechs = krb5`.

If the application has any keytabs, tell gssproxy about them: `cred_store =
keytab:/etc/path/to.keytab`.  Then change the user and group permissions on
the keytab so that the application can't read them (but gssproxy can): `chown
root:root /etc/path/to.keytab`.

The next step is to figure out what sets your application apart from others
that may be running on the system.  gssproxy requires specifying a uid (`euid
= appuser`), but if it runs as root, that may not be enough.

Fortunately, gssproxy also allows executable name matching.  This checks the
canonical, full path to an executable.  Your program must be a native ELF (or
similar) - it cannot be an interpreted program (as that would allow all
programs running under the interpreter to access gssproxy as if they were
yours).  This field is therefore optional.

(If that's still not enough to distinguish your application, don't worry -
just see the later section on using a custom socket.)

In the end, we would end up with a config file that looks a bit like this:

```INI
[service/my_app]
    mechs = krb5
    cred_store = keytab:/etc/path/to.keytab
    euid = appuser
    program = /usr/local/bin/my_app
```

And tell gssproxy to use the new configuration file: `systemctl
try-reload-or-restart gssproxy`

## Configuring the application

In order for the application to attempt to use gssproxy, it needs an
environment variable set: `GSS_USE_PROXY=yes`.  (For more information on
environment variable configuration, see the man page for gssproxy-mech - `man
8 gssproxy-mech`.)

How this is configured will of course vary application to application.

If launching by hand from a shell, just prepend it to the invocation:
`GSS_USE_PROXY=yes my_app`.

If launching using sysvinit, you'll probably need to edit the invocation in
**/etc/init.d/my_app** (there may be a nicer way, but it's system-dependent).

If launching using systemd (these instructions assume Fedora), create a new
file at **/etc/systemd/system/my_app.service** and make it look like this:

```INI
.include /lib/systemd/system/my_app.service
[Service]
Environment=GSS_USE_PROXY=1
```

and then reload the systemd state: `systemctl daemon-reload`.

From there, (re)start your application and you're off to the races!

## Aside: using a custom socket

Normally, gssproxy traffic all runs over the same socket, which typically
lives in **/var/lib/gssproxy/default.sock**.  However, gssproxy can listen on
many sockets, and can distinguish services this way.  Using a custom socket
for your service is a two part configuration: configure the client, and
configure gssproxy.

To configure gssproxy, we need to tell the daemon to open another socket.
Pick a path (**/var/lib/gssproxy/my_app.sock** is good) and modify the service
configuration to use it: `socket = /var/lib/gssproxy/my_app.sock`.  Then
reload gssproxy's configuration: `systemctl try-reload-or-restart gssproxy`.

To configure the client, we need to set another environment variable:
`GSSPROXY_SOCKET`.  So, we set that in the same way we set `GSS_USE_PROXY`
(i.e., `GSSPROXY_SOCKET=/var/lib/gssproxy/my_app.sock`), and launch.

## How to know it's working

By far the easiest way to tell is to have a configuration working *without*
gssproxy, and then migrate to one *with* gssproxy.  If the environment
variable is set in the process, and everything keeps working, then you know
everything is all set.

A similar thing is true of the keytabs: if the application can't read them,
but continues to function, then everything is working correctly.

That's not always possible, though.  In that case, you can look at gssproxy's
logs to see connections from your service.  First, set `debug_level = 1` in
**/etc/gssproxy/gssproxy.conf**, and then have gssproxy reload its
configuration (`systemctl reload gssproxy`).  Then, in the gssproxy logs (for
systemd, this is `journalctl -xfu gssproxy`), you should see lines like:

    may 08 12:48:52 freeipa.rharwood.biz gssproxy[27144]: [CID 13][2018/05/08 16:48:52]: gp_rpc_execute: executing 6 (GSSX_ACQUIRE_CRED) for service "ipa-httpd", euid: 48,socket: (null)

This happens to be taken from a user connecting to the webui on a freeipa
instance.  It was preceeded at some point by a line announcing the conection.
This line says that it's executing a call to (something like)
`gss_acquire_cred()` on behalf of the "ipa-httpd" configured service, which is
uid 48 (i.e., apache), and that it's assigned ID 13 to this session.
