# Setting KRB5_TRACE for gssproxy

Enabling `KRB5_TRACE` output as described in `# man gssproxy.conf`:

**At level 3 and above, KRB5_TRACE output is logged. If KRB5_TRACE was already set in the execution environment, trace output is sent to its value instead.**

can be done either by including `KRB5_TRACE=/path/to/location` when executing gssproxy at the command line or by including a location within a drop file loaded by systemd. Systemd uses unix sockets to redirect outputs to the journal, and this means `/dev/stderr` ends up pointing to a name that cannot be used as a path to open the stderr descriptor. A drop file is necessary to record `KRB5_TRACE` information as gssproxy directs `KRB5_TRACE` to `/dev/stderr` by default.

The output can be directed to any location, but gssproxy only has write access to `/var/lib/gssproxy` by default. This means that for a host system using SELinux either a custom module policy will need to be created or SELinux will need to be put into permissive mode.

As setting `KRB5_TRACE` output is not designed to be continually logged nor treated as traditional log output, it is recommended to direct the trace output to `/var/lib/gssproxy`.

- Increase gssproxy debugging so that `KRB5_TRACE` information is logged as described in `# man gssproxy.conf`.

~~~~
# echo ' debug_level = 3' >> /etc/gssproxy/gssproxy.conf
~~~~

 - Create a drop file for gssproxy to log `KRB5_TRACE` output to a file under `/var/lib/gssproxy`

~~~~
# mkdir /etc/systemd/system/gssproxy.service.d

# cat <<EOF > /etc/systemd/system/gssproxy.service.d/99-trace.conf
[Service]
Environment=KRB5_TRACE=/var/lib/gssproxy/gssproxy.krb5_trace
EOF
~~~~

 - Reload the service files and restart the `gssproxy` service

~~~~
# systemctl daemon-reload

# systemctl restart gssproxy
~~~~
