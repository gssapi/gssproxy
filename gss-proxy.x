/*
 * Copyright (c) 2011, Secure Endpoints Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This is an initial attempt at creating an XDR representation of the
 * GSS-API for the implementation of a GSS proxy client/server protocol,
 * both over local IPC (for NFS and various other applications) and
 * remote (for ssh-agent-like functionality).
 *
 * This is a work-in-progress.  However, rpcgen(1) on Ubuntu does
 * compile this file.
 *
 * Because the GSS-API is based on "functions" and XDR is the basis for
 * ONC RPC (which is based on "procedures") we use "_arg_" and "_res_"
 * affixes to name structures, and we use those structures to encode
 * function arguments and results, respectively.
 *
 * Naming functions are unified into one RPC for now.  Clients are
 * expected to not call the proxy for GSS_Import_name() calls unless the
 * name type is GSS_C_NT_EXPORTED_NAME.  Calls to GSS_Import/
 * Canonicalize/Display_name() can done in one RPC.
 *
 * Credentials functions are also unified.  The idea is to not have to
 * do multiple round-trips to acquire credentials then inquire them.
 *
 * GSS_Init/Accept_sec_context() similarly return all the information
 * about a context that the app could want, including an exported
 * security context token (so the app can import it).
 *
 * We support stateful and stateless proxy server implementations both.
 *
 * We use gssx_ as a prefix to avoid colliding with the C bindings.
 *
 * We use the XDR '*' operator to denote "optional" fields in structs.
 * But for optional gss_OID and gss_OID_set arguments, and only those
 * types of arguments,  we use empty OID/OID set to denote "not present"
 * (presently no GSS functions have any special semantics for empty
 * OIDs/OID sets; we can use '*' in the future if any new functions are
 * added with such semantics).
 */

/* Generic base types */
typedef opaque                  utf8string<>;
typedef opaque                  octet_string<>;

/* GSS base types */
typedef unsigned hyper          gssx_uint64;    /* 64-bit for future proofing */
typedef unsigned hyper          gssx_qop;
typedef octet_string            gssx_buffer;    /* empty -> empty, !missing */
typedef octet_string            gssx_OID;       /* empty -> GSS_C_NO_OID */
typedef gssx_OID                gssx_OID_set<>; /* empty -> GSS_C_NO_OID_SET */
enum gssx_cred_usage {GSSX_C_INITIATE = 1, GSSX_C_ACCEPT = 2, GSSX_C_BOTH = 3};
typedef unsigned hyper          gssx_time;      /* seconds since Unix epoch */

/* Extensions types.  This file is the registry of extension types for now. */
enum gssx_ext_id {
    GSSX_EXT_CRED_STORE_UNIX_KERNEL = 0,        /* see below */
    GSSX_EXT_CRED_STORE_UNIX_USER = 1           /* see below */
};

/* Extensions */
struct gssx_typed_hole {
    /*
     * Values of ext_type with the high bit set will be for private use;
     * all other values will require registration.
     */
    gssx_ext_id         ext_type;
    octet_string        ext_data;
};

/* Avoid round-trips for GSS_Display_status() */
struct gssx_status {
    gssx_uint64         major_status;
    gssx_OID            mech;           /* to interpret minor_status by */
    gssx_uint64         minor_status;
    utf8string          major_status_string; /* localized; see below */
    utf8string          minor_status_string; /* localized; see below */
    octet_string        server_ctx;    /* see caller context, below */
};

/*
 * Caller context.
 *
 * Caller contexts are objects that are created by the caller.  But the
 * server may return some octet string that the client must use with the
 * same call context in the future (the server does so by sending
 * server_ctx in the gssx_status struct; see above).
 *
 * This is useful to help the proxy server find user credentials, for
 * example.  And for conveying locale information for status display
 * string localization.  It could be used in the future for other
 * extensions.  It could be used for gss_set_context_option() for some
 * context options, for example.
 *
 * A credential store is always implied in the GSS-API, but for a proxy
 * GSS protocol we need an *option* to make the credential store explicit.
 * The cred_store field of the caller context is used to identify a
 * credential store.
 *
 * For some implementations and/or use contexts cred_store may be an
 * empty octet string.  Others might encode such things as environment
 * variables in it.
 */
struct gssx_call_ctx {
    gssx_uint64         client_ctx_id; /* a client-local unique id */
    octet_string        server_ctx;    /* server-assigned (see above) */
    utf8string          locale;        /* for status display string L10N */
    gssx_typed_hole     cred_store;    /* cred store "handle" or reference */
    gssx_typed_hole     extensions<>;
};

/*
 * Example/possible structs to encode and use as cred_store.
 *
 * Two examples are given.
 *
 * Note that a gss proxy server implementation must be very careful about how it
 * interprets cred_store information.  In particular it must not allow clients
 * to access credential stores that they should not have access to -- that is,
 * the gss proxy server must implement some form of authorization.
 *
 * An implementation that have an instance of a gss proxy daemon per-user or
 * per-session might use IPC endpoints with appropriate permissions and simply
 * ignore cred_store information from the caller, assuming instead that any
 * caller that has access to the daemon's IPC endpoint has permission to access
 * the proxy daemon instance's underlying credential store.
 *
 * Other implementations might have a single gss proxy daemon for all users on a
 * system, in which case the authorization decision is likely more complex.
 */

/*
 * Example/possible struct for identifying credential stores in the case that
 * the caller is a Unix kernel module.  For example, an NFS/AFS/Lustre/other
 * module might want to upcall to a gss proxy daemon to initiate or accept a
 * security context.
 *
 * In some OSes the kernel might have information available that can help
 * identify a credential store for the desired operation.  For example, on Linux
 * the kernel might have keyring information useful for locating a Kerberos
 * ccache.
 *
 * Other OSes might not have a use for this at all.  For example, on Solaris the
 * gss proxy might be able to use an API like door_ucred(3DOOR) to get all the
 * information it needs to find the caller's credential store.
 */
struct gssx__unix_kernel_cred_store {
    /*
     * A unix kernel proxy client will want to tell the proxy server
     * most/every relevant details about the client process/thread
     * on behalf of which the kernel is doing this call.  Unless the
     * kernel can do this through an IPC-specific mechanism (e.g.,
     * door_ucred(3DOOR) in Solaris).
     *
     * The proxy server needs this information for either or both of
     * these two purposes: a) credential store identification, b)
     * authorization.  Some implementations might not need this for
     * (b) (e.g., where there's a per-user or per-session proxy
     * server, in which case access to the IPC endpoint might be
     * authorization enough).
     */
    gss_uint64          pid; /* process ID */
    gss_uint64          tid; /* thread ID */
    gss_uint64          euid;/* effective UID */
    gss_uint64          pag; /* PAG; 0 -> no PAG */
    /*
     * Lots of other things could be relevant here, such as keyring
     * IDs, labels, ...
     *
     * A lot of this might be obviated by SCM_CREDENTIALS or
     * door_ucred(3DOOR) type interfaces, so for some OSes this
     * structure might well be empty.
     */
};

/*
 * Example/possible cred_store extension for user-land gss proxy clients on a
 * typical Unix system.  This structure simply includes environment variables
 * from the caller's environment, such as KRB5CCNAME and KRB5_KTNAME for
 * Kerberos.  See authorization notes above!
 */
struct gssx__unix_user_cred_store {
    utf8string          environment<>;  /* for non-kernel clients */
};

/*
 * For NAME we don't use a plain opaque handle representation.  Our aim
 * is to be able to implement GSS_Import_name() and GSS_Display_name()
 * without talking to the proxy server (e.g., when the name type is not
 * an exported name type), and to unify those and GSS_Canonicalize_name()
 * and GSS_Get/Set_name_attribute() into one RPC.
 */
struct gssx_name {
    /* Non-MNs MUST have these; MNs MAY have these */
    gssx_buffer         *display_name;
    gssx_OID            name_type;
    /* MNs MUST have at least one exported name */
    gssx_buffer         *exported_name;
    gssx_buffer         *exported_composite_name;
    /* Name attributes */
    gssx_typed_hole     desired_name_attributes<>;
    gssx_typed_hole     actual_name_attributes<>;
    gssx_typed_hole     extensions<>;
};

/*
 * CREDENTIAL and CONTEXT handles
 */
struct gssx_cred_info {
    /* GSS_Inquire_cred_by_mech() outputs */
    gssx_name           MN;
    gssx_OID            mech;
    gssx_cred_usage     cred_usage;
    gssx_time           initiator_time_rec;
    gssx_time           acceptor_time_rec;
    gssx_typed_hole     cred_options<>;
    gssx_typed_hole     extensions<>;
};
struct gssx_ctx_info {
    /* GSS_Inquire_context() outputs */
    gssx_OID            mech;
    gssx_name           src_name;
    gssx_name           targ_name;
    gssx_time           lifetime;
    gssx_uint64         ctx_flags;
    bool                locally_initiated;
    bool                open;
    gssx_typed_hole     context_options<>;
    gssx_typed_hole     extensions<>;
};
enum gssx_handle_type { GSSX_C_HANDLE_SEC_CTX = 0, GSSX_C_HANDLE_CRED = 1 };
union gssx_handle_info switch (gssx_handle_type handle_type) {
    case GSSX_C_HANDLE_CRED:
        gssx_cred_info  cred_info<>; /* One per cred element */
    case GSSX_C_HANDLE_SEC_CTX:
        gssx_ctx_info   sec_ctx_info;
    default:
        octet_string    extensions;   /* Future handle types */
};
struct gssx_handle {
    gssx_handle_info    handle_info;        /* Has handle type */
    octet_string        *handle;            /* Server-specific bits */
    octet_string        *exported_handle;   /* Local standard form */
    bool                needs_release;      /* For stateful proxies */
};
typedef gssx_handle     gssx_ctx;
typedef gssx_handle     gssx_cred;

/*
 * We should probably come up with a standard RFC4121 context export
 * token structure here.  We only need, basically, the session keys and
 * initial token sequence numbers (plus, for clients that want to proxy
 * per-msg token functions to stateless servers, we'd need a sequence
 * number window structure).  Things like authz-data can be placed in
 * the gssx_name's exported_composite_name or extensions fields, in the
 * handle_info.
 */

/* Channel bindings */
struct gssx_cb {
    /*
     * Address type CB is deprecated; use only application_data.
     * See RFCs 5056 and 5554.
     */
    gssx_uint64         initiator_addrtype; /* deprecated */
    gssx_buffer         initiator_address;  /* deprecated */
    gssx_uint64         acceptor_addrtype;  /* deprecated */
    gssx_buffer         acceptor_address;   /* deprecated */
    gssx_buffer         application_data;
    /*
     * There's no extensibility here, and there must not be.  All CB
     * extensibility in the GSS-API now is a matter of
     * application_data formatting conventions.
     */
};
typedef struct gssx_cb gssx_cb;

/* One RPC for all handle release functions */
struct gssx_arg_release_handle {
    gssx_call_ctx       call_ctx;
    gssx_handle         cred_handle;
};
struct gssx_res_release_handle {
    gssx_status         status;
};

/* We unify GSS_Import/Canonicalize_name() */
struct gssx_arg_import_and_canon_name {
    gssx_call_ctx       call_ctx;
    gssx_name           input_name;
    gssx_OID            mech;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_import_and_canon_name {
    gssx_status         status;
    gssx_name           *output_name;
    gssx_typed_hole     extensions<>;
};

struct gssx_arg_get_call_context {
    gssx_call_ctx       call_ctx;
};
struct gssx_res_get_call_context {
    gssx_status         status;
    gssx_call_ctx       call_ctx;
};

/*
 * We unify GSS_Acquire/Add_cred() here.
 *
 * GSS_Add_cred() is only meaningful here for stateful proxy server
 * implementations.  Stateless ones will always output a new handle;
 * stateful ones will modify the given input handle if desired, but we
 * still include a handle in the result for the handle_info.
 */
struct gssx_arg_acquire_cred {
    gssx_call_ctx       call_ctx;
    gssx_cred           *input_cred_handle;
    bool                add_cred_to_input_handle;
    gssx_name           *desired_name; /* absent -> GSS_C_NO_NAME */
    gssx_time           time_req;
    gssx_OID_set        desired_mechs; /* no need to dist. empty vs. absent */
    gssx_cred_usage     cred_usage;
    gssx_time           initiator_time_req;
    gssx_time           acceptor_time_req;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_acquire_cred {
    gssx_status         status;
    gssx_cred           *output_cred_handle; /* includes info */
    gssx_typed_hole     extensions<>;
};

struct gssx_arg_store_cred {
    gssx_call_ctx       call_ctx;
    gssx_cred           input_cred_handle;
    gssx_cred_usage     cred_usage;
    gssx_OID            desired_mech;
    bool                overwrite_cred;
    bool                default_cred;
};
struct gssx_res_store_cred {
    gssx_status         status;
    gssx_OID_set        elements_stored;
    gssx_cred_usage     cred_usage_stored;
};

/*
 * Security context functions
 *
 * We don't need GSS_Inquire_context(), nor GSS_Import/
 * Export_sec_context().  These are all subsumed into
 * GSS_Init/Accept_sec_context() in this protocol.
 */
struct gssx_arg_init_sec_context {
    gssx_call_ctx       call_ctx;
    gssx_ctx            *context_handle;
    gssx_cred           *cred_handle; /* absent -> GSS_C_NO_CREDENTIAL */
    gssx_name           *target_name; /* absent -> GSS_C_NO_NAME */
    gssx_OID            mech_type;
    gssx_uint64         req_flags;
    gssx_time           time_req;
    gssx_cb             *input_cb; /* input channel bindings */
    gssx_buffer         *input_token;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_init_sec_context {
    gssx_status         status;
    gssx_ctx            *context_handle; /* includes info outputs */
    gssx_buffer         *output_token;
    gssx_typed_hole     extensions<>;
};

struct gssx_arg_accept_sec_context {
    gssx_call_ctx       call_ctx;
    gssx_ctx            *context_handle;
    gssx_cred           *cred_handle; /* absent -> GSS_C_NO_CREDENTIAL */
    gssx_buffer         input_token;
    gssx_cb             *input_cb; /* input channel bindings */
    gssx_typed_hole     extensions<>;
};
struct gssx_res_accept_sec_context {
    gssx_status         status;
    gssx_ctx            *context_handle; /* includes info outputs */
    gssx_buffer         *output_token;
    gssx_cred           *delegated_cred_handle;
    gssx_typed_hole     extensions<>;
};

/*
 * We provide per-message token functions for testing and bootstrap
 * purposes: a client might not have a provider for a given mechanism,
 * in which case the proxy can provide per-message token functions to
 * the client.  This is primarily useful for testing that the
 * client-side provider and the server-side provider have interoperable
 * per-message token functions, which can be especially important for
 * kernel-mode client use cases.
 *
 * The results of these functions have an optional context_handle output
 * so that stateless servers can store sequence number windows and such
 * things in the returned handle.
 *
 * Server support for this is optional.  Clients should really not need
 * this.
 */
struct gssx_arg_get_mic {
    gssx_call_ctx       call_ctx;
    gssx_ctx            context_handle;
    gssx_qop            qop_req;
    gssx_buffer         message_buffer;
};
struct gssx_res_get_mic {
    gssx_status         status;
    gssx_ctx            *context_handle;
    gssx_buffer         token_buffer; /* empty on error */
    gssx_qop            *qop_state;
};

struct gssx_arg_verify_mic {
    gssx_call_ctx       call_ctx;
    gssx_ctx            context_handle;
    gssx_buffer         message_buffer;
    gssx_buffer         token_buffer;
};
struct gssx_res_verify_mic {
    gssx_status         status;
    gssx_ctx            *context_handle;
    gssx_qop            *qop_state;
};

/*
 * We use gssx_buffer<> to make implementation of iov variants slightly
 * easier.
 */
struct gssx_arg_wrap {
    gssx_call_ctx       call_ctx;
    gssx_ctx            context_handle;
    bool                conf_req;
    gssx_buffer         message_buffer<>;
    gssx_qop            qop_state;
};
struct gssx_res_wrap {
    gssx_status         status;
    gssx_ctx            *context_handle;
    gssx_buffer         token_buffer<>;
    bool                *conf_state;
    gssx_qop            *qop_state;
};

struct gssx_arg_unwrap {
    gssx_call_ctx       call_ctx;
    gssx_ctx            context_handle;
    gssx_buffer         token_buffer<>;
    gssx_qop            qop_state;
};
struct gssx_res_unwrap {
    gssx_status         status;
    gssx_ctx            *context_handle;
    gssx_buffer         message_buffer<>;
    bool                *conf_state;
    gssx_qop            *qop_state;
};

struct gssx_arg_wrap_size_limit {
    gssx_call_ctx       call_ctx;
    gssx_ctx            context_handle;
    bool                conf_req;
    gssx_qop            qop_state;
    gssx_uint64         req_output_size;
};
struct gssx_res_wrap_size_limit {
    gssx_status         status;
    gssx_uint64         max_input_size;
};

/* Various inquiry functions */
struct gssx_arg_indicate_mechs {
    gssx_call_ctx       call_ctx;
};
struct gssx_res_indicate_mechs {
    gssx_status         status;
    gssx_OID_set        mech_set;
};

struct gssx_arg_indicate_mechs_by_attr {
    gssx_call_ctx       call_ctx;
    gssx_OID_set        desired_mech_attrs;
    gssx_OID_set        except_mech_attrs;
    gssx_OID_set        critical_mech_attrs;
};
struct gssx_res_indicate_mechs_by_attr {
    gssx_status         status;
    gssx_OID_set        mech_set;
};

struct gssx_arg_inquire_attrs_for_mech {
    gssx_call_ctx       call_ctx;
    gssx_OID            mech;
};
struct gssx_res_inquire_attrs_for_mech {
    gssx_status         status;
    gssx_OID_set        mech_attrs;
    gssx_OID_set        known_mech_attrs;
};

struct gssx_arg_display_mech_attr {
    gssx_call_ctx       call_ctx;
    gssx_OID            mech_attr;
};
struct gssx_res_display_mech_attr {
    gssx_status         status;
    gssx_buffer         name;
    gssx_buffer         short_desc;
    gssx_buffer         long_desc;
};

program GSSPROXY {
    version GSSPROXYVERS {
    gssx_res_indicate_mechs
        GSSX_INDICATE_MECHS(gssx_arg_indicate_mechs) = 1;
    gssx_res_indicate_mechs_by_attr
        GSSX_INDICATE_MECHS_BY_ATTR(gssx_arg_indicate_mechs_by_attr) = 2;
    gssx_res_inquire_attrs_for_mech
        GSSX_INQUIRE_ATTRS_FOR_MECH(gssx_arg_inquire_attrs_for_mech) = 3;
    gssx_res_display_mech_attr
        GSSX_DISPLAY_MECH_ATTR(gssx_arg_display_mech_attr) = 4;
    gssx_res_get_call_context
        GSSX_GET_CALL_CONTEXT(gssx_arg_get_call_context) = 5;
    gssx_res_import_and_canon_name
        GSSX_IMPORT_AND_CANON_NAME(gssx_arg_import_and_canon_name) = 6;
    gssx_res_acquire_cred
        GSSX_ACQUIRE_CRED(gssx_arg_acquire_cred) = 7;
    gssx_res_store_cred
        GSSX_STORE_CRED(gssx_arg_store_cred) = 8;
    gssx_res_init_sec_context
        GSSX_INIT_SEC_CONTEXT(gssx_arg_init_sec_context) = 9;
    gssx_res_accept_sec_context
        GSSX_ACCEPT_SEC_CONTEXT(gssx_arg_accept_sec_context) = 10;
    gssx_res_release_handle
        GSSX_RELEASE_HANDLE(gssx_arg_release_handle) = 11;
    gssx_res_get_mic
        GSSX_GET_MIC(gssx_arg_get_mic) = 12;
    gssx_res_verify_mic
        GSSX_VERIFY(gssx_arg_verify_mic) = 13;
    gssx_res_wrap
        GSSX_WRAP(gssx_arg_wrap) = 14;
    gssx_res_unwrap
        GSSX_UNWRAP(gssx_arg_unwrap) = 15;
    gssx_res_wrap_size_limit
        GSSX_WRAP_SIZE_LIMIT(gssx_arg_wrap_size_limit) = 16;
    } = 1;
} = 412345; /* XXX obtain from Oracle (Bill Baker, I think) */
