# Introduction

GSS-Proxy has been built as a way to provide an abstraction layer between a GSS client (typically an application) and the credentials being used.
This is normally used to perform privilege separation, so that a client application can authenticate/use secure channels via GSSAPI without direct access to keying material.

In the NFS server case we extended the GSS-Proxy protocol to be able to talk directly to the in kernel NFSD. The reason we did this was to allow the kernel NFS server to handle big tickets like those containing a MS-PAC payload that may be received by a Microsoft client.
For the NFS client case GSS-Proxy allows to operate impersonation behind the scenes so that access to files is "always on" but network level security is maintained.

## NFS Server

To use GSS-Proxy with the NFS server you need a recent enough kernel. Anything more recent than 3.10 should work just fine.

At the time of writing the choice between using the classic rpc.scvgssd protocol and the new gssproxy protocol is determined *once* at runtime. Once the kernel "chooses" the method it cannot be changed. A reboot will be necessary.

The kernel chooses what protocol to use on the first authentication request it receives. It checks if a gssproxy "client" has registered in which case it will bind to use the gssproxy protocol, otherwise it will select the classic rpc.svcgssd protocol and stick to that one.

The gssproxy client registers to the kernel by performing 2 actions in the following order:

- creates a unix socket for kernel communication in /var/run/gssproxy.sock (this path is hardcoded in the kernel and cannot be changed at this time)
- writes 1 byte in the proc file /proc/net/rpc/use-gss-proxy (the client must be ready to accept a connection from the kernel when this is done, as the kernel we check that the socket is available)

NOTE: GSS-Proxy does not use libnfsidmap (nor /etc/idmap.conf) for three reasons:
- principal to local name mapping is already implemented in krb5.conf via the `auth_to_local` option and that automatically integrates with any nsswitch providers that feed users to the system (like SSSD, Winbind, etc) that do proper caching and filtering without requiring a completely separate mapping system
- because of the above we can avoid a lot of code to handle libnfsidmap in gssproxy that is not needed, without loss of functionality, and in fact with gain of functionality via the above mentioned mapping systems (no manual krb5.conf configuration needed when a system is using Winbindd/SSSD and is joined to a domain)
- libidmap is not thread safe and this is a deal breaker

The simplest GSS-Proxy configuration file to act as a NFSD helper is the following:
```
[gssproxy]

[service/nfs-server]
  mechs = krb5
  socket = /run/gssproxy.sock
  cred_store = keytab:/etc/krb5.keytab
  trusted = yes
  kernel_nfsd = yes
  euid = 0
```

Let's see what this means, line by line:

- The service is named (an arbitrary name so that the admin has a hint of what it is used for) 'nfs-server'.
- It limits the GSSAPI supported mechanisms to the 'krb5' mechanism (which is the only one that NFS supports).
- It sets the kernel socket name /run/gssproxy.sock (on my system /var/run is a symlink to /run)
- It defines that the server's keys are stored in /etc/krb5.keytab (the customary place, you should have both host/ and nfs/ keys in there).
- It marks the peer as trusted, which means we will believe the kernel when it says it is connecting on behalf of a specific user even if the credentials (getpeercon) on the other side of the socket say otherwise.
- It enables the kernel extensions to the protocol (the context is exported as a lucid context for example, and a list of resolved credentials is returned if authentication succeeds)
- It prevents any user but root/kernel (i.e. anything matching euid = 0 as returned by getpeercon) from connecting to the socket.


This is pretty much all that is needed to use GSS-Proxy as the user-space helper for the kernel NSFD daemon when GSSAPI authentication of a client is required.


## NFS Client

The NFS client case is a little bit more complicated. For starter, at the time of writing the NFS client code in kernel still uses the classic protocol and can only talk with the rpc.gssd service. The interaction with GSS-Proxy, in the client case, is more subtle.

The way GSS-Proxy is configured in the client case is pretty much the normal userspace interposition, performed at the libgssapi level.
The GSSAPI library should be configured (either in /etc/gss.conf or /etc/gss.conf.d/gssproxy.conf) to load the GSS-Proxy interposer plugin which allows GSS-Proxy to intercept GSSAPI calls and sprinkle a little magic on the operations (as well as performing privilege separation).

Example gss.conf
```
# GSS-API mechanism plugins
#
# Mechanism Name	Object Identifier		Shared Library Path			Other Options
gssproxy_v1		2.16.840.1.113730.3.8.15.1	@libdir@/gssproxy/proxymech.so		<interposer>
```

Once this is done rpc.gssd must be started with the following environment variable defined:
```
GSS_USE_PROXY="yes"
```
This instructs the interposer plugin to act, otherwise the interposer plugin will silently fallback to standard GSSAPI behavior.


In the client case the GSS-Proxy is usually employed when special cases need to be handled. For example on unmanned systems people may need to use kerberized NFS but no human being is present to manually create a credential cache.
In these cases there are 2 options that can be employed based on the admin preference and the local KDC capabilities.
NOTE: we assume a modern version of rpc.gssd which drops privileges to the requesting uid before calling GSSAPI.

### Keytab based Client Initiation

The GSS-Proxy daemon can easily initiate client credentials automatically based on a keytab.
In this case services (for example an Apache server) on the NFS client machines need to access a krb5 protected mount unattended, but they can be given a Kerberos identity (principal) and matching set of keys (stored in keytabs).

The following configuration allows this mode of operation:
```
[service/nfs-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_store = client_keytab:/var/lib/gssproxy/clients/%U.keytab
  cred_usage = initiate
  allow_any_uid = yes
  euid = 0
```

Let's see what this means, line by line:

- The service is named (an arbitrary name so that the admin has a hint of what it is used for) 'nfs-client'.
- It limits the GSSAPI supported mechanisms to the 'krb5' mechanism (which is the only one that NFS supports).
- It defines that the client's nfs keys are stored in /etc/krb5.keytab (the customary place).
- It defines that ccaches created by GSS-Proxy for user's credentials are stored under /var/lib/gssproxy/clients and use a format specifier to have a different name for each user. "%U" translated to the use UID Number.
- It defines that keytabs with user's keys are stored under /var/lib/gssproxy/clients and use a format specifier to have a different name for each user. "%U" translated to the use UID Number.
- It marks the service usable only for initiation (this is important to avoid allowing any user to receive connections using the system keytab).
- It marks the service accessible by any user on the system. Each user will only be able to use their own credentials if any are available.


You may notice that an explicit UNIX socket is not configured, this mean this service is exposed on the default socket that is available at /var/lib/gssproxy/default.sock by default.

The important bit here is the user's keytabs which are stored under /var/lib/gssproxy/clients.
If you have a HTTP service running as user Apache (uid=48) that needs to connect unattended then keys for this user can be stored under /var/lib/gssproxy/clients/48.keytab and this user can now always successfully use kerberized NFS w/o any additional configuration (no cronjobs or other wrapper services necessary). The necessary credentials will be fetched when needed from the KDC, on request.

Note that if credentials are not available GSS-Proxy will return control to rpc.gssd and the usual crawling for credentials will be attempted.

Note that if you need only one specific service to connect you may also use a more restricted service definition.

Example for a system where only the Apache server uses unattended kerberized NFS mounts.
```
[service/apache]
  mechs = krb5
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_apache
  cred_store = client_keytab:/var/lib/gssproxy/clients/httpd.keytab
  cred_usage = initiate
  euid = 48
```

In this example, only the Apache user (euid = 48) is permitted to attempt to use the GSS-Proxy service, and a fixed name for ccaches and keytab is used instead of a uid number dependent one.


### User Impersonation via Constrained Delegation

The previous method works fine if you have a limited set of services running on the machine that need unattended access to a NFS file system, but what to do if you have actual physical users? Handling user's keytabs is annoying, both because it is a liability and because user's passwords can be changed by the users (and when that happens the keytab becomes invalid and needs to be regenerated). It also become cumbersome pretty quickly if there are very many users.

Yet in many cases there are users that run long lasting jobs on relatively trusted (by the admin) machines and want to make sure their jobs won't fail after a day because their credentials expire and they suddenly lose access to the NFS share. (Or maybe the job is even batch scheduled so the user never even has a chance to leave credentials on the machine actually running the job).

In this cases, if the KDC support Constrained Delegation and specifically the
[s4u2self and s4u2proxy protocol extensions](https://ssimo.org/blog/id_011.html),
then the administrator can "empower" the NFS client machine to impersonate
arbitrary users.  NOTE: not all KDCs support these extensions or have way to
properly configure them. The 2 main products that do are Microsoft's
[Active Directory](http://en.wikipedia.org/wiki/Active_Directory) and the
Linux oriented [FreeIPA](http://www.freeipa.org).  NOTE: The FreeIPA s4u2proxy
implementation can also precisely limit which services can be reached via
delegation, for example allow the NFS client machine to obtain tickets
exclusively for a specific NFS server, and no other service at all.

The following configuration allows this mode of operation:
```
[service/nfs-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_usage = initiate
  allow_any_uid = yes
  impersonate = true
  euid = 0
```

Let's see what this means, line by line:

- The service is named (an arbitrary name so that the admin has a hint of what it is used for) 'nfs-client'.
- It limits the GSSAPI supported mechanisms to the 'krb5' mechanism (which is the only one that NFS supports).
- It defines that the client's nfs keys are stored in /etc/krb5.keytab (the customary place, this is required for impersonation).
- It defines that ccaches created by GSS-Proxy for user's credentials are stored under /var/lib/gssproxy/clients and use a format specifier to have a different name for each user. "%U" translated to the use UID Number.
- It marks the service usable only for initiation (this is important to avoid allowing any user to receive connections using the system keytab).
- It marks the service accessible by any user on the system. Each user will only be able to use their own credentials if any are avilable.
- It instructs gssproxy to attempt impersonation of the requesting user.


So what happens here if a user process tries to walk a mount point ?

- the kernel asks rpc.gssd to establish a secure context with the server
- rpc.gssd asks GSSAPI for user credentials
- the GSSAPI mechproxy module intercepts the requests and forwards it to GSS-Proxy
- GSS-Proxy sees that a user requested initiation, it furthermore notices that the matching service allows impersonation. NOTE: that GSS-Proxy at this time uses a quite unsophisticated resolution mechanism to map the user uid to a principal name, it simply gets the user name from the system and tries to use that as the principal name (using the default realm).
- GSS-Proxy gets initial credentials with the system keytab, then it tries to acquire a ticket for itself on behalf of the user (s4u2self).
- GSS_Proxy finally tries to get a ticket for the target system using the previously obtained ticket as evidence (s4u2proxy).

If all goes well the NFS Client now can impersonate the user and successfully connect to the NFS server.

