# GSS-PROXY Protocol Documentation

The GSS-PROXY protocol is an RPC protocol based on ONCRPC v2.

## Protocol Definition

The protocol definition file is currently maintained in GIT here:
https://github.com/gssapi/gssproxy/blob/master/x-files/gss_proxy.x

The protocol is not stable yet and it is being revised while we progress prototyping client and server code, however the parts used by the Linux kernel driver are considered final and will see no backward incompatible changes.

Long term we will probably submit an actual RFC to the IETF to standardize it.

## Extensions

There are 2 "extensions" currently being worked on for the Linux kernel client.

### Lucid context export type
The Linux Kernel needs a special export and serialize Lucid context.

To inform the proxy that this special format should be returned from the gss_accept_se_context call, the client needs to set a gssx_option in call_ctx structure.

The option field is set to the string "exported_context_type"

The value field is set to the string "linux_lucid_v1"

When these fields are set the proxy will return a lucid context formatted accordingly to the Linux Kernel needs instead of a normal exported context buffer.

### Export credentials flag
When the accept_sec_context call is completed the Linux Kernel needs to be given a credential set containing all the user uid, gid and secondary gids so that is can properly handle access control.

To inform the proxy that this data is needed the clientneeds to set a gssx_option in call_ctx structure.

The option field is set to the string "exported_creds_type"

The value field is set to the string "linux_creds_v1"

When these fields are set the proxy will return a buffer containing the credentials in the accpet_sec_context call response buffer as a gssx_option.

The option field is set to the string "linux_creds_v1"

The value field contains the creds buffer.

This buffer is composed of the fixed fields of 32 bit size and an array of 32 bit values as follows: ` <uid>, <primary gid>, <count>, <array of 'count' secondary gids> `

### Krb5 Set Allowed Enctypes
Allows to send a krb5 mechanism specific option to set the allowed encryption types for a credential.

When a client obtains valid credentials it can attach an option to a gssx_cred_element element of a gssx_cred credential to indicate to the server the desire to limit the allowed encryption types used on said credential before the following call.
On the next call, when said credentials are transmitted to the Gss Proxy, the server will probe the received credentials and will attempt a call to gss_krb5_set_allowed_enctypes() using the data provided in the credentials received.

The gssx_cred option should be placed in a gssx_cred_element whose mech type is one of the recognized krb5 mechanism OIDs.

The option field is set to the string "krb5_set_allowed_enctype_values"

The value field contains a buffer of 32bit integers

The length of the buffer divided by 4 determines the number of enctypes conveyed. The array of integers is stored in machine dependent byte order, and is cast directly into an array of krb5_enctypes.


