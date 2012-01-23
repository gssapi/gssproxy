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
 *                         README First!
 *
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
 * We unify functions as much as possible into as few RPCs as possible.
 * For example, we unify GSS_Import/Canonicalize/Display_name().  We
 * also unify GSS_Acquire/Add_cred() and the credentials handle inquiry
 * functions.  This way we reduce the number of round-trips needed to
 * use the GSS proxy protocol effectively.
 *
 * Similarly, GSS_Init/Accept_sec_context() return all the information
 * about a context that the app could want, including an exported
 * security context token (so the app can import it).
 *
 * All general meta-data functions, such as GSS_Indicate_mechs() and
 * GSS_Inquire_attrs_for_mech(), are unified as well.
 *
 * We support stateful and stateless proxy server implementations both.
 * Stateless servers will need to store various internal state on the
 * client side, in the form of serialized credential handle references
 * (e.g., ccache names) and exported security context tokens even for
 * partially established security contexts.  Stateless servers will
 * generally want to MAC state stored on the client side.
 *
 * We use gssx_ as a prefix to avoid colliding with the C bindings.
 *
 * We use the XDR '*' operator to denote "optional" fields in structs.
 * But for optional gss_OID and gss_OID_set arguments, and only those
 * types of arguments,  we use empty OID/OID set to denote "not present"
 * (presently no GSS functions have any special semantics for empty
 * OIDs/OID sets; we can use '*' in the future if any new functions are
 * added with such semantics).
 *
 * Most/all RPC arguments/results have typed holes for extensibility.
 * Most/all "handles" have typed holes for extensibility.  Name
 * attributes, credential options, and security context options are all
 * first-class types rather than extensions for those typed holes.
 *
 * For functions like GSS_Set_name_attribute(), GSS_Set_cred_option(),
 * and GSS_Set_sec_ctx_option(), the way these are intended to be
 * implemented with this GSS proxy protocol is as follows:
 *
 *  - For name attributes the client must call the IMPORT_AND_CANON_NAME
 *    RPC once again for each additional name attribute.  The input_name
 *    argument be the same as returned by the previous call to the same
 *    RPC.
 *
 *    This means that an RPC (round trip) is needed for each name
 *    attribute to be set.  This is a result of the semantics of
 *    GSS_Set_name_attribute() and cannot be avoided.
 *
 *  - For credential handle options the client can call ACQUIRE_CRED
 *    with cred_options.  If called with an existing credential handle
 *    and no new elements are needed then no elements will be added to
 *    the output credential, but the desired cred_options should be set
 *    in the new credential (and will be visible).  This allows a
 *    default credential handle to be acquired with cred_options in just
 *    one round-trip for the first option.  Each additional cred_option
 *    requires an additional round-trip with today's
 *    GSS_Set_cred_option().
 *
 *    Note that supported cred_options are indicated on a per-mechanism
 *    basis by the INDICATE_MECHS RPC.
 *
 *  - For security context options the options must be passed in on the
 *    initial call to INIT/ACCEPT_SEC_CONTEXT (and may be repeated on
 *    the remaining calls for a security context, but only the first
 *    will matter).
 *
 *    Note that supported context_options are indicated on a
 *    per-mechanism basis by the INDICATE_MECHS RPC.
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

/*
 * Major status codes will be per-RFC2744, cast to gssx_uint64.
 *
 * XXX Should we define GSSX_S_...?  Should #include the RFC2744 headers
 * here?
 */

/* Extensions types.  This file is the registry of extension types for now. */
enum gssx_ext_id {
    GSSX_EXT_NONE = 0
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

/* Mechanism attributes */
struct gssx_mech_attr {
    gssx_OID            attr;
    gssx_buffer         name;
    gssx_buffer         short_desc;
    gssx_buffer         long_desc;
    gssx_typed_hole     extensions<>;
};

/* Mechanism meta-data */
struct gssx_mech_info {
    gssx_OID            mech;
    gssx_OID_set        name_types;
    gssx_OID_set        mech_attrs;
    gssx_OID_set        known_mech_attrs;
    gssx_OID_set        cred_options;
    gssx_OID_set        sec_ctx_options;
    utf8string          provider_names<>;
    utf8string          provider_paths<>;
    gssx_typed_hole     extensions<>;
};

/* Name attributes are {attribute name, attribute value} */
struct gssx_name_attr {
    gssx_buffer         attr;
    gssx_buffer         value;
    gssx_typed_hole     extensions<>;
};

/* Credential and security context options are {option OID, option value} */
struct gssx_option {
    gssx_OID            option;
    gssx_buffer         value;
    gssx_typed_hole     extensions<>;
};

/*
 * We avoid round-trips for GSS_Display_status() by always sending
 * displayed status messages.  These are intended to be localized to the
 * locale specified by the client (see below).
 *
 * Note that the minor_status is not really meaningful unless the
 * mechanism specifies specific minor_status numeric values, which no
 * mechanism does!  The server repeats the mechanism OID here for
 * convenience, so the client can have a single structure that contains
 * the mechanism OID and minor_status value for whatever purpose the
 * client might put them to.
 *
 * The server_ctx value is opaque and intended for the client to replace
 * its' caller context's server_ctx value with.
 */
struct gssx_status {
    gssx_uint64         major_status;
    gssx_OID            mech;
    gssx_uint64         minor_status;
    utf8string          major_status_string;
    utf8string          minor_status_string;
    octet_string        server_ctx;
    gssx_typed_hole     extensions<>;
};

/*
 * Caller context.
 *
 * Caller contexts are objects that are created by the caller.  But the
 * server may return some octet string (in gssx_status; see above) that
 * the client must use in its call context in the future.
 *
 * This is useful to help the proxy server find user credentials, for
 * example.  And for conveying locale information for status display
 * string localization.  It could be used in the future for other
 * extensions.  It could be used for gss_set_context_option() for some
 * context options, for example.
 *
 * A credential store is always implied in the GSS-API, but for a proxy
 * GSS protocol we may need an *option* to make the credential store
 * explicit.  If we do need that option we'll use the extensions field
 * for it.
 */
struct gssx_call_ctx {
    utf8string          locale;     /* for status display string L10N */
    octet_string        server_ctx; /* server-assigned (see above) */
    gssx_typed_hole     extensions<>;
};

/*
 * For NAMEs we don't use a plain opaque handle representation.
 *
 * Our aim is to be able to implement GSS_Import_name() and
 * GSS_Display_name() without talking to the proxy server (e.g., when
 * the name type is not an exported name type), and to unify those and
 * GSS_Canonicalize_name() and GSS_Get/Set_name_attribute() into one
 * RPC.
 *
 * We support multi-MNs by having arrays of exported name tokens, rather
 * than just one, just in case we end up with multi-MN extensions.
 */
struct gssx_name {
    /* Non-MNs MUST have these; MNs MAY have these */
    gssx_buffer         *display_name;
    gssx_OID            name_type;
    /* MNs MUST have at least one exported name form */
    gssx_buffer         exported_name<>;
    gssx_buffer         exported_composite_name<>;
    /* Name attributes */
    gssx_name_attr      name_attributes<>;
    /* Future extensions */
    gssx_typed_hole     extensions<>;
};

/*
 * CREDENTIAL HANDLEs are really just a description plus whatever state
 * reference or encoded (and protected) state the server needs.
 */
struct gssx_cred {
    /* GSS_Inquire_cred_by_mech() outputs */
    gssx_name           MN;
    gssx_OID            mech;
    gssx_cred_usage     cred_usage;
    gssx_time           initiator_time_rec;
    gssx_time           acceptor_time_rec;
    gssx_option         cred_options<>;
    /*
     * Server-side state reference or encoded state; may or may not
     * require releasing.  This may be just a ccache name, or an encoded
     * list of URI-like strings, for example, or it might be an exported
     * credential, possibly encrypted and/or MACed with a server secret
     * key.
     *
     * Stateful servers MUST be able to clean up unreferenced state
     * automatically, using an LRU/LFU type cache.  However, stateful
     * servers SHOULD (or at least MAY) indicate statefulness so that
     * the client can release server-side state sooner than the server
     * might otherwise do it.
     */
    octet_string        cred_handle_reference;
    bool                needs_release;
    /* Extensions */
    gssx_typed_hole     extensions<>;
};

/*
 * Security CONTECT HANDLEs consist of a description of the security
 * context and an exported security context token or (if the server
 * can't export partially established security contexts) a server-side
 * state reference.
 */
struct gssx_ctx {
    /* The exported context token, if available */
    octet_string        *exported_context_token;   /* exported context token */
    octet_string        *state;
    /*
     * Stateful servers MUST be able to clean up unreferenced state
     * automatically, using an LRU/LFU type cache.  However, stateful
     * servers SHOULD (or at least MAY) indicate statefulness so that
     * the client can release server-side state sooner than the server
     * might otherwise do it.
     */
    bool                needs_release;
    /* GSS_Inquire_context() outputs */
    gssx_OID            mech;
    gssx_name           src_name;
    gssx_name           targ_name;
    gssx_time           lifetime;
    gssx_uint64         ctx_flags;
    bool                locally_initiated;
    bool                open;
    gssx_option         context_options<>;
    gssx_typed_hole     extensions<>;
};

/*
 * We have a union type for CREDENTIAL and security CONTEXT HANDLEs so
 * that we can have a unified handle release RPC (which is needed only
 * when the server is stateful).
 */
enum gssx_handle_type { GSSX_C_HANDLE_SEC_CTX = 0, GSSX_C_HANDLE_CRED = 1 };
union gssx_handle switch (gssx_handle_type handle_type) {
    case GSSX_C_HANDLE_CRED:
        gssx_cred       cred_info<>; /* One per cred element */
    case GSSX_C_HANDLE_SEC_CTX:
        gssx_ctx        sec_ctx_info;
    default:
        octet_string    extensions;   /* Future handle types */
};

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

/* Various mechanism inquiry functions, all unified into one RPC */
struct gssx_arg_indicate_mechs {
    gssx_call_ctx       call_ctx;
};
struct gssx_res_indicate_mechs {
    gssx_status         status;
    gssx_mech_info      mechs<>;
    gssx_mech_attr      mech_attr_descs<>;
    gssx_ext_id         supported_extensions<>;
    gssx_typed_hole     extensions<>;
};

/* We unify GSS_Import/Canonicalize_name() and GSS_Get/Set_name_attribute() */
struct gssx_arg_import_and_canon_name {
    gssx_call_ctx       call_ctx;
    gssx_name           input_name;
    gssx_OID            mech;
    gssx_name_attr      name_attributes<>;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_import_and_canon_name {
    gssx_status         status;
    gssx_name           *output_name;
    gssx_typed_hole     extensions<>;
};

/* We probably don't need this RPC */
struct gssx_arg_get_call_context {
    gssx_call_ctx       call_ctx;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_get_call_context {
    gssx_status         status;
    octet_string        server_call_ctx;    /* server-assigned (see above) */
    gssx_typed_hole     extensions<>;
};

/* We unify GSS_Acquire/Add_cred() here */
struct gssx_arg_acquire_cred {
    gssx_call_ctx       call_ctx;
    gssx_option         cred_options<>;
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

/* GSS_Export/Import_cred() are not unified */
struct gssx_arg_export_cred {
    gssx_call_ctx       call_ctx;
    gssx_cred           input_cred_handle;
    gssx_cred_usage     cred_usage;
    gssx_typed_hole     extensions<>;
};

struct gssx_res_export_cred {
    gssx_status         status;
    gssx_cred_usage     usage_exported;
    octet_string        *exported_handle;   /* exported credential token */
    gssx_typed_hole     extensions<>;
};

struct gssx_arg_import_cred {
    gssx_call_ctx       call_ctx;
    octet_string        exported_handle;   /* exported credential token */
    gssx_typed_hole     extensions<>;
};
struct gssx_res_import_cred {
    gssx_status         status;
    gssx_cred           *output_cred_handle; /* includes info */
    gssx_typed_hole     extensions<>;
};

/* GSS_Store_cred() */
struct gssx_arg_store_cred {
    gssx_call_ctx       call_ctx;
    gssx_cred           input_cred_handle;
    gssx_cred_usage     cred_usage;
    gssx_OID            desired_mech;
    bool                overwrite_cred;
    bool                default_cred;
    gssx_typed_hole     extensions<>;
};
struct gssx_res_store_cred {
    gssx_status         status;
    gssx_OID_set        elements_stored;
    gssx_cred_usage     cred_usage_stored;
    gssx_typed_hole     extensions<>;
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
    gssx_option         context_options<>;
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
    gssx_option         context_options<>;
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
 * kernel-mode client use cases.  (I.e., setup an NFS client without a
 * kernel-mode GSS mechanism provider and test it against an NFS server
 * that does have a kernel-mode GSS mechanism provider, and vice-versa.)
 *
 * The results of these functions have an optional context_handle output
 * so that stateless servers can store sequence number windows in the
 * returned handle.
 *
 * Server support for this is optional.  Clients should really not need
 * this for any purpose other than testing.
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

program GSSPROXY {
    version GSSPROXYVERS {
    /* rpcgen knows to automatically generate a NULLPROC */
    gssx_res_indicate_mechs
        GSSX_INDICATE_MECHS(gssx_arg_indicate_mechs) = 1;
    gssx_res_get_call_context
        GSSX_GET_CALL_CONTEXT(gssx_arg_get_call_context) = 2;
    gssx_res_import_and_canon_name
        GSSX_IMPORT_AND_CANON_NAME(gssx_arg_import_and_canon_name) = 3;
    gssx_res_export_cred
        GSSX_EXPORT_CRED(gssx_arg_export_cred) = 4;
    gssx_res_import_cred
        GSSX_IMPORT_CRED(gssx_arg_import_cred) = 5;
    gssx_res_acquire_cred
        GSSX_ACQUIRE_CRED(gssx_arg_acquire_cred) = 6;
    gssx_res_store_cred
        GSSX_STORE_CRED(gssx_arg_store_cred) = 7;
    gssx_res_init_sec_context
        GSSX_INIT_SEC_CONTEXT(gssx_arg_init_sec_context) = 8;
    gssx_res_accept_sec_context
        GSSX_ACCEPT_SEC_CONTEXT(gssx_arg_accept_sec_context) = 9;
    gssx_res_release_handle
        GSSX_RELEASE_HANDLE(gssx_arg_release_handle) = 10;
    gssx_res_get_mic
        GSSX_GET_MIC(gssx_arg_get_mic) = 11;
    gssx_res_verify_mic
        GSSX_VERIFY(gssx_arg_verify_mic) = 12;
    gssx_res_wrap
        GSSX_WRAP(gssx_arg_wrap) = 13;
    gssx_res_unwrap
        GSSX_UNWRAP(gssx_arg_unwrap) = 14;
    gssx_res_wrap_size_limit
        GSSX_WRAP_SIZE_LIMIT(gssx_arg_wrap_size_limit) = 15;
    } = 1;
} = 412345; /* XXX obtain from Oracle (Bill Baker, I think) */
