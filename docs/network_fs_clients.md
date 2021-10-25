# Introduction

Following changes to cifs.upcall, extending its functionality to leverage gssapi for ticket acquisition, 99-nfs-client.conf has been renamed to 99-network-fs-clients.conf. This allows the upcall programs for client side NFS and SMB, rpc.gssd and cifs.upcall, to leverage the same configuration file. However, there may be circumstances where having differentiated access for each remote filesystem is preferred or even necessary.

## Creating configuration files

If different behavior for client side NFS and SMB is needed:

1) Remove /etc/gssproxy/99-network-fs-clients.conf

2) Create configuration files for cifs-client and nfs-client services. The `program =` option **must** be included if both programs are going to access the default socket, `/var/lib/gssproxy/default.sock`

~~~~
# cat /etc/gssproxy/99-cifs-client.conf
[service/cifs-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_store = client_keytab:/var/lib/gssproxy/clients/%U.keytab
  cred_usage = initiate
  allow_any_uid = yes
  trusted = yes
  euid = 0
  program = /usr/sbin/cifs.upcall
~~~~

~~~~
[service/nfs-client]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_store = client_keytab:/var/lib/gssproxy/clients/%U.keytab
  cred_usage = initiate
  allow_any_uid = yes
  trusted = yes
  euid = 0
  program = /usr/sbin/rpc.gssd
~~~~

3) Customize the above files as needed. The existing docs/NFS.md file discusses Keytab based Client initiation as well as User Impersonation and Constrainted Delegation. Resource Base Constrained Delegation is also possible and requires no additional client side configuration changes as RBCD is a server side configuration change.
