# Using GSS-Proxy for Apache httpd operation

The traditional approach for performing Kerberos authentication in Apache 2.* is to use the mod_auth_gssapi (historically, mod_auth_kerb would have been used) module. When using this module, the Apache process must have read access to a keytab (configured with the ```GssapiCredStore``` option, or the default ```/etc/krb5.keytab```). This is not optimal from a security point of view as all websites can potentially get access to the key material. GSS-Proxy allows you to implement privilege separation for the Apache httpd server by removing access to the keytab(s) while preserving Kerberos authentication functionality.

This page describes a setup which works starting with Fedora 21 with
gssproxy-0.4.1-1.fc21.x86_64, httpd-2.4.16-1.fc21.x86_64, and
mod_auth_gssapi-1.3.0-2.fc21.x86_64.  It works on similar versions of RHEL as
well.  It describes two concurrent goals that can be implemented together or independently.

Goals:
1. authenticate web clients to the httpd service
1. authenticate the ```apache``` user (running the httpd process) to access and serve network filesystem content mounted with Kerberos, e.g., NFS using ```sec=krb5``` (in some form)

## Setting up GSS-Proxy

For the first goal, the proxy will require a keytab for the service principal (HTTP/server-name@REALM). When using IPA server, command

```
# ipa service-add HTTP/server-name
```

will create the service principal. On an IPA-enrolled client machine, the

```
# ipa-getkeytab -s $(awk '/^server =/ {print $3}' /etc/ipa/default.conf) -k /etc/gssproxy/http.keytab -p HTTP/$(hostname -f)
```

will retrieve the keytab for the principal. In the following configuration snippets we assume it is stored in ```/etc/gssproxy/http.keytab```. The permissions are set to 400, owner root. The Apache user does not have access to the keytab.

We need to know the Apache user numerical id to put it in the configuration
file, because GSS-Proxy uses the effective uid to distinguish the services. On
my installation, the uid is 48. Symbolic uids are also supported (e.g.,
"httpd" or "apache").

We add a new section to the gssproxy configuration.  To do this, copy the
```examples/80-httpd.conf``` file to ```/etc/gssproxy/80-httpd.conf```.  (If
you are using a monolithic config file at ```/etc/gssproxy/gssproxy.conf```,
make sure the HTTP stanza precedes any ```allow_any_uid=yes``` sections.)

For the second goal, the proxy will require a keytab for the user principal (apache@REALM).  Again, the uid used here is 48, but it must match whatever httpd is running as.

```
# ipa user-add apache --uid 48 --gidnumber 48 --homedir /usr/share/httpd  --shell /sbin/nologin --first Apache --last 'web server'
```

This keytab is retrieved much like above, but the destination is different to match the following config snippet.  Again, it's important that the Apache user does not have access to this keytab either.

```
# ipa-getkeytab -s $(awk '/^server =/ {print $3}' /etc/ipa/default.conf) -k /var/lib/gssproxy/clients/48.keytab -p apache/$(awk '/^realm =/ {print $3}' /etc/ipa/default.conf)
```

We now need one more gssproxy configuration section.  Copy ```examples/99-network-fs-clients.conf``` to ```/etc/gssproxy/99-network-fs-clients.conf``` (preferred) or add to the monolithic config file.


We then start the service:

```
# systemctl restart gssproxy.service
# systemctl enable gssproxy.service
```

## Setting up Apache

For this first goal (described above), we need to know the location or directory that we want to protect. For testing purposes, we can create a simple file

```
# echo OK > /var/www/html/private
```

and configure mod_auth_gssapi to protect that location:

```
<Location /private>
  AuthType GSSAPI
  AuthName "GSSAPI Login"
  Require valid-user
</Location>
```

in some ```/etc/httpd/conf.d/*.conf``` file. Note that no keytab is configured here since direct access is not needed or wanted -- instead the keytab(s) are accessed indirectly by communication with GSS-Proxy via ```/var/lib/gssproxy/default.sock```.

Furthermore, we need to tell the libraries to use the GSS-Proxy - create ```/etc/systemd/system/httpd.service``` with content

```
.include /lib/systemd/system/httpd.service
[Service]
Environment=GSS_USE_PROXY=1
```

Reload the configuration:

```
systemctl daemon-reload
```

The second goal may get rather specific to while the networked file system is needed and how it is used, but a trivial example would be to let Apache just provide a file index and serve everything in a given directory.

~~~
<Directory "/srv/www/pub/">
    Options Indexes MultiViews
    Require all granted
</Directory>
~~~

Note that there is no GSSAPI configuration here.  The gssproxy configuration above sufficiently authenticates the apache user principal as a file system client.  You might however add the GSSAPI settings similiar to above if you *also* wanted to authenticate the web clients trying to acess this directory.


When we now (re)start the Apache service

```
# systemctl restart httpd.service
# systemctl enable httpd.service
```

we should be able to make HTTP requests against the server and they will be authenticated if the client has a valid Kerberos ticket.
