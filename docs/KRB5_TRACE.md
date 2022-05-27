# Setting KRB5_TRACE for gssproxy

This document explain how to obtain KRB5 tracing output.

It is possible to get KRB5 tracing information together with gssproxy
debugging information on Standard Error[^1] by simply running the
process at debug level 3: `gssproxy -d --debug-level=3`

In cases where it may be convenient to have a separate file with KRB5
tracing it is possible to do so by making sure the KRB5_TRACE
environment is set when the gssproxy process is executed[^2].

The output can be directed to any location, but gssproxy only has write
access to `/var/lib/gssproxy` by default. This means that for a host
system using SELinux either a custom module policy will need to be
created or SELinux will need to be put into permissive mode.

As setting `KRB5_TRACE` output is not designed to be used in production
nor treated as traditional log output, it is recommended to direct the
trace output to `/var/lib/gssproxy` to avoid changes to SELinux policy.

Ways to obtain KRB5 tracing output:

- Increase gssproxy debugging so that `KRB5_TRACE` information is logged
as described in `# man gssproxy.conf`.

```
# echo ' debug_level = 3' >> /etc/gssproxy/gssproxy.conf
# pkill -HUP gssproxy
```

- Create a systemd drop file for gssproxy to log `KRB5_TRACE` output
```
# mkdir /etc/systemd/system/gssproxy.service.d
# cat <<EOF > /etc/systemd/system/gssproxy.service.d/99-trace.conf
[Service]
Environment=KRB5_TRACE=/var/lib/gssproxy/gssproxy.krb5_trace
EOF

# systemctl daemon-reload
# systemctl restart gssproxy
```

---
[^1]: Until recently, an [issue](https://github.com/gssapi/gssproxy/issues/44)
with how the standard error is setup **required** redirection to an
actual file in order to obtain any KRB5 Tracing information. If you are
using an older version of gssproxy you will need to set the KRB5_TRACE
environment variable to an actual file, changing debug level will not
be sufficient.

[^2]: Setting KRB5_TRACE will cause KRB5 tracing information to be
emitted regradless of gssproxy's debug level.
