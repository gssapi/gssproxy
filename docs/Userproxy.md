# Introduction

The GSS-Proxy hs been built for two purposes: to server the kernel NFSD and for
privilege separation in userspace.

The privilege separation feature has been used, so far, to allow unprivileged
user processes to use keys (keytabs) that are held by root (or potentially a
different user).

However there is another case where privilege separation is useful, and that is
usage of contained applications in a user session, for example using flatpaks,
which are a containerized solution that aims, among other things, at
constraining what apps within the flatpak can do and not give full unfettered
access to the user session.

Userproxy is tailored to this kind of use.

NOTE: Do not donfuse the userproxy mode of operations with the run_as_user
configure option, thes eare completely orthogonal things.

NOTE: carefully read the Behavior section

## Setting up Userproxy mode

If GSS-Proxy is started with the argument -u|--userproxy it switched to
userproxy mode. This has some profound consequences on the behavior of
GSS-Proxy.

### Configuration

First of all the configuration file is completely ignored and not even parsed,
instead a single-service configuration is synthetized that allows only
processes from the same euid to connect to the proxy socket. The idea is to
allow any operations the user may be normally doing, just bridging a confined
user application to the main user session to avoid direct access to TGT but
otherwise not restricting any use.

### Communication Socket

The default Socket is changed to be in the user runtime directory:
$XDG_RUNTIME_DIR/gssprosy/default.sock
If the $XDG_RUNTIME_DIR environment variable is not set or the directory doe
not exist, the proxy will fail to start.
The 'gssproxy' directory will be created in $XDG_RUNTIME_DIR if it does not
exists before opening the default.sock unix-socket file.

The -s option can be used to provide a custom socket location, in this case the
whole directory structure needs to be in place or startup will fail.

### Behavior

Because this mode is intended to provide full access to a user session,
including potentially further proxing out to another gssproxy instance, the
userproxy mode does not prevent loops in GSSAPI by internally setting the
GSS_USE_PROXY env var to "no", as the default mode does.

This allows the following to work:
[container (GSSAPI app)] -> [user session (GSS-Proxy)] -> [privileged
(GSS-Proxy)]

It is also the reason why a non standard socket is used in this mode, so that
the proxymech plugin running withing GSSAPI in the GSS-Proxy's userproxy
itself does not, in fact, try to reconnect back and deadlock in a loop.

Within the container it is recommended to bind mount the userproxy created
directory on the standard location which is generally:
/var/lib/gssproxy

Additionally in the container the USE_GSS_PROXY env var needs to be set to
the value "yes" unless the proxymech.so pluging within the container has been
built to always enable proxing.
For example, a container may custom build the gss module plugin with:
./configure --enable-always-interpose \
            --enable-only-gss-module
