# Using GSS-Proxy for Apache httpd operation

The traditional approach for performing Kerberos authentication in Apache 2.* is to use the mod_auth_gssapi (historically, mod_auth_kerb would have been used) module. When using this module, the Apache process must have read access to a keytab (configured with the ```GssapiCredStore``` option, or the default ```/etc/krb5.keytab```) containing keys for the HTTP service. This is not optimal from a security point of view as all websites can potentially get access to the key material. GSS-Proxy allows to implement privilege separation for the Apache httpd server by removing access to the keytab while preserving Kerberos authentication functionality.

This page describes a setup which works starting with Fedora 21 with
gssproxy-0.4.1-1.fc21.x86_64, httpd-2.4.16-1.fc21.x86_64, and
mod_auth_gssapi-1.3.0-2.fc21.x86_64.  It works on similar versions of RHEL as
well.

## Setting up GSS-Proxy

The proxy will need access to the HTTP/server-name@realm's keytab. When using IPA server, command

```
# ipa service-add HTTP/server-name
```

will create the service principal. On an IPA-enrolled client machine, the

```
# ipa-getkeytab -s $(awk '/^server =/ {print $3}' /etc/ipa/default.conf) -k /etc/gssproxy/http.keytab -p HTTP/$(hostname -f)
```

will retrieve the keytab for the principal. In the following configuration snippet we assume it is stored in ```/etc/gssproxy/http.keytab```. The permissions are set to 400, owner root. The Apache user does not have access to the keytab.

We need to know the Apache user numerical id to put it in the configuration
file, because GSS-Proxy uses the effective uid to distinguish the services. On
my installation, the uid is 48. Symbolic uids are also supported (e.g.,
"httpd" or "apache").

We add a new section to the gssproxy configuration.  To do this, copy the
```examples/80-httpd.conf``` file to ```/etc/gssproxy/80-httpd.conf```.  (If
you are using a monolithic config file at ```/etc/gssproxy/gssproxy.conf```,
make sure the HTTP stanza preceeds any ```allow_any_uid=yes``` sections.)

We then start the service:

```
# systemctl restart gssproxy.service
# systemctl enable gssproxy.service
```

## Setting up Apache

For Apache, we need to know the location or directory that we want to protect. For testing purposes, we can create a simple file

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

in some ```/etc/httpd/conf.d/*.conf``` file. Note that the path to the keytab is not configured here since it will not be needed -- communication with GSS-Proxy via ```/var/lib/gssproxy/default.sock``` will be used instead.

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

When we now (re)start the Apache service

```
# systemctl restart httpd.service
# systemctl enable httpd.service
```

we should be able to make HTTP requests against the server and they will be authenticated if the client has a valid Kerberos ticket.
