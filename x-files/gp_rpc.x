/*
 * ONC RPC request/reply header XDR.
 *
 * Note that this XDR is extracted from RFC1831 and massaged so that
 * rpcgen(1) accepts it, but it is intended to be wire-compatible with
 * RFC1831.
 *
 * Also, in order to avoid symbol naming conflicts, we prefix "gp_" and
 * "GP_" to all symbols from RFC1831.  "GP" stands for "GSS proxy".
 */

enum gp_rpc_auth_flavor {
    GP_RPC_AUTH_NONE       = 0,
    GP_RPC_AUTH_SYS        = 1,
    GP_RPC_AUTH_SHORT      = 2,
    GP_RPC_AUTH_DH         = 3,
    GP_RPC_RPCSEC_GSS      = 6
	/* and more to be defined */
};

struct gp_rpc_opaque_auth {
    gp_rpc_auth_flavor flavor;
    opaque body<400>;
};

enum gp_rpc_msg_type {
    GP_RPC_CALL  = 0,
    GP_RPC_REPLY = 1
};

enum gp_rpc_reply_status {
    GP_RPC_MSG_ACCEPTED = 0,
    GP_RPC_MSG_DENIED   = 1
};

enum gp_rpc_accept_status {
    GP_RPC_SUCCESS       = 0, /* RPC executed successfully       */
    GP_RPC_PROG_UNAVAIL  = 1, /* remote hasn't exported program  */
    GP_RPC_PROG_MISMATCH = 2, /* remote can't support version #  */
    GP_RPC_PROC_UNAVAIL  = 3, /* program can't support procedure */
    GP_RPC_GARBAGE_ARGS  = 4, /* procedure can't decode params   */
    GP_RPC_SYSTEM_ERR    = 5  /* e.g. memory allocation failure  */
};

enum gp_rpc_reject_status {
    GP_RPC_RPC_MISMATCH = 0, /* RPC version number != 2          */
    GP_RPC_AUTH_ERROR = 1    /* remote can't authenticate caller */
};

enum gp_rpc_auth_status {
    GP_RPC_AUTH_OK           = 0,  /* success                        */
    /*
     * failed at remote end
     */
    GP_RPC_AUTH_BADCRED      = 1,  /* bad credential (seal broken)   */
    GP_RPC_AUTH_REJECTEDCRED = 2,  /* client must begin new session  */
    GP_RPC_AUTH_BADVERF      = 3,  /* bad verifier (seal broken)     */
    GP_RPC_AUTH_REJECTEDVERF = 4,  /* verifier expired or replayed   */
    GP_RPC_AUTH_TOOWEAK      = 5,  /* rejected for security reasons  */
    /*
     * failed locally
     */
    GP_RPC_AUTH_INVALIDRESP  = 6,  /* bogus response verifier        */
    GP_RPC_AUTH_FAILED       = 7,  /* reason unknown                 */
    /*
     * AUTH_KERB errors; deprecated.  See [RFC2695]
     */
    GP_RPC_AUTH_KERB_GENERIC = 8,  /* kerberos generic error */
    GP_RPC_AUTH_TIMEEXPIRE = 9,    /* time of credential expired */
    GP_RPC_AUTH_TKT_FILE = 10,     /* problem with ticket file */
    GP_RPC_AUTH_DECODE = 11,       /* can't decode authenticator */
    GP_RPC_AUTH_NET_ADDR = 12,     /* wrong net address in ticket */
    /*
     * RPCSEC_GSS GSS related errors
     */
    GP_RPC_RPCSEC_GSS_CREDPROBLEM = 13, /* no credentials for user */
    GP_RPC_RPCSEC_GSS_CTXPROBLEM = 14   /* problem with context */
};

struct gp_rpc_mismatch_info {
    unsigned int low;
    unsigned int high;
};

union gp_rpc_reply_union switch (gp_rpc_accept_status status) {
    case GP_RPC_SUCCESS:
	opaque results[0];
	/*
	 * procedure-specific results start here
	 */
    case GP_RPC_PROG_MISMATCH:
	gp_rpc_mismatch_info mismatch_info;
    default:
	/*
	 * Void.  Cases include PROG_UNAVAIL, PROC_UNAVAIL,
	 * GARBAGE_ARGS, and SYSTEM_ERR.
	 */
	void;
};

struct gp_rpc_accepted_reply {
    gp_rpc_opaque_auth verf;
    gp_rpc_reply_union reply_data;
};

union gp_rpc_rejected_reply switch (gp_rpc_reject_status status) {
    case GP_RPC_RPC_MISMATCH:
	gp_rpc_mismatch_info mismatch_info;
    case GP_RPC_AUTH_ERROR:
	gp_rpc_auth_status status;
};
struct gp_rpc_call_header {
    unsigned int rpcvers;       /* must be equal to two (2) */
    unsigned int prog;
    unsigned int vers;
    unsigned int proc;
    gp_rpc_opaque_auth cred;
    gp_rpc_opaque_auth verf;
    /* procedure-specific parameters start here */
};

union gp_rpc_reply_header switch (gp_rpc_reply_status status) {
    case GP_RPC_MSG_ACCEPTED:
	gp_rpc_accepted_reply accepted;
    case GP_RPC_MSG_DENIED:
	gp_rpc_rejected_reply rejected;
};

union gp_rpc_msg_union switch (gp_rpc_msg_type type) {
    case GP_RPC_CALL:
	gp_rpc_call_header chdr;
    case GP_RPC_REPLY:
	gp_rpc_reply_header rhdr;
};

struct gp_rpc_msg {
    unsigned int xid;
    gp_rpc_msg_union header;
};

