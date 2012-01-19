/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "config.h"
#include <stdint.h>
#include <errno.h>
#include "gp_utils.h"
#include "gp_rpc_process.h"

struct gp_rpc_fn_set gp_xdr_set[] = {
    { /* NULLPROC */
        (xdrproc_t)xdr_void,
        (xdrproc_t)xdr_void,
        NULL
    },
    { /* GSSX_INDICATE_MECHS */
        (xdrproc_t)xdr_gssx_arg_indicate_mechs,
        (xdrproc_t)xdr_gssx_res_indicate_mechs,
        gp_indicate_mechs
    },
    { /* GSSX_GET_CALL_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_get_call_context,
        (xdrproc_t)xdr_gssx_res_get_call_context,
        gp_get_call_context
    },
    { /* GSSX_IMPORT_AND_CANON_NAME */
        (xdrproc_t)xdr_gssx_arg_import_and_canon_name,
        (xdrproc_t)xdr_gssx_res_import_and_canon_name,
        gp_import_and_canon_name
    },
    { /* GSSX_EXPORT_CRED */
        (xdrproc_t)xdr_gssx_arg_export_cred,
        (xdrproc_t)xdr_gssx_res_export_cred,
        gp_export_cred
    },
    { /* GSSX_IMPORT_CRED */
        (xdrproc_t)xdr_gssx_arg_import_cred,
        (xdrproc_t)xdr_gssx_res_import_cred,
        gp_import_cred
    },
    { /* GSSX_ACQUIRE_CRED */
        (xdrproc_t)xdr_gssx_arg_acquire_cred,
        (xdrproc_t)xdr_gssx_res_acquire_cred,
        gp_acquire_cred
    },
    { /* GSSX_STORE_CRED */
        (xdrproc_t)xdr_gssx_arg_store_cred,
        (xdrproc_t)xdr_gssx_res_store_cred,
        gp_store_cred
    },
    { /* GSSX_INIT_SEC_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_init_sec_context,
        (xdrproc_t)xdr_gssx_res_init_sec_context,
        gp_init_sec_context
    },
    { /* GSSX_ACCEPT_SEC_CONTEXT */
        (xdrproc_t)xdr_gssx_arg_accept_sec_context,
        (xdrproc_t)xdr_gssx_res_accept_sec_context,
        gp_accept_sec_context
    },
    { /* GSSX_RELEASE_HANDLE */
        (xdrproc_t)xdr_gssx_arg_release_handle,
        (xdrproc_t)xdr_gssx_res_release_handle,
        gp_release_handle
    },
    { /* GSSX_GET_MIC */
        (xdrproc_t)xdr_gssx_arg_get_mic,
        (xdrproc_t)xdr_gssx_res_get_mic,
        gp_get_mic
    },
    { /* GSSX_VERIFY */
        (xdrproc_t)xdr_gssx_arg_verify_mic,
        (xdrproc_t)xdr_gssx_res_verify_mic,
        gp_verify
    },
    { /* GSSX_WRAP */
        (xdrproc_t)xdr_gssx_arg_wrap,
        (xdrproc_t)xdr_gssx_res_wrap,
        gp_wrap
    },
    { /* GSSX_UNWRAP */
        (xdrproc_t)xdr_gssx_arg_unwrap,
        (xdrproc_t)xdr_gssx_res_unwrap,
        gp_unwrap
    },
    { /* GSSX_WRAP_SIZE_LIMIT */
        (xdrproc_t)xdr_gssx_arg_wrap_size_limit,
        (xdrproc_t)xdr_gssx_res_wrap_size_limit,
        gp_wrap_size_limit
    }
};

static int gp_rpc_decode_call_header(struct gp_rpc_call *call,
                                     uint32_t *xid,
                                     uint32_t *proc,
                                     gp_rpc_accept_status *acc,
                                     gp_rpc_reject_status *rej)
{
    struct gp_rpc_call_header *chdr;
    bool decoded;

    decoded = xdr_gp_rpc_msg(&call->xdr_ctx, &call->msg);
    if (!decoded) {
        return EFAULT;
    }

    *xid = call->msg.xid;

    if (call->msg.header.type != GP_RPC_CALL) {
        *acc = GP_RPC_GARBAGE_ARGS;
        return EINVAL;
    }

    chdr = &call->msg.header.gp_rpc_msg_union_u.chdr;

    if (chdr->rpcvers != 2) {
        *rej = GP_RPC_RPC_MISMATCH;
        return EACCES;
    }
    if (chdr->prog != GSSPROXY) {
        *acc = GP_RPC_PROG_UNAVAIL;
        return EINVAL;
    }
    if (chdr->vers != GSSPROXYVERS) {
        *acc = GP_RPC_PROG_MISMATCH;
        return EINVAL;
    }
    if (chdr->proc < 1 || chdr->proc > 15) {
        *acc = GP_RPC_PROC_UNAVAIL;
        return EINVAL;
    }
    if (chdr->cred.flavor != GP_RPC_AUTH_NONE) {
        *rej = GP_RPC_AUTH_ERROR;
        return EACCES;
    }

    *proc = chdr->proc;
    *acc = GP_RPC_SUCCESS;
    return 0;
}

static int gp_rpc_decode_call(struct gp_rpc_call *call,
                              uint32_t *xid,
                              uint32_t *proc,
                              union gp_rpc_arg *arg,
                              gp_rpc_accept_status *acc,
                              gp_rpc_reject_status *rej)
{
    bool xdrok;
    int ret;

    ret = gp_rpc_decode_call_header(call, xid, proc, acc, rej);
    if (ret) {
        return ret;
    }

    xdrok = gp_xdr_set[*proc].arg_fn(&call->xdr_ctx, (char *)arg);
    if (!xdrok) {
        *acc = GP_RPC_GARBAGE_ARGS;
        return EINVAL;
    }

    return 0;
}

static int gp_rpc_encode_reply_header(struct gp_rpc_reply *reply,
                                      uint32_t xid, int err,
                                      gp_rpc_accept_status acc,
                                      gp_rpc_reject_status rej)
{
    gp_rpc_reply_header *rhdr;
    gp_rpc_accepted_reply *accepted;
    gp_rpc_rejected_reply *rejected;
    bool encoded;

    reply->msg.xid = xid;
    reply->msg.header.type = GP_RPC_REPLY;

    rhdr = &reply->msg.header.gp_rpc_msg_union_u.rhdr;
    accepted = &rhdr->gp_rpc_reply_header_u.accepted;
    rejected = &rhdr->gp_rpc_reply_header_u.rejected;

    switch (err) {
    case EFAULT:
        return EFAULT;
    case EACCES:
        rhdr->status = GP_RPC_MSG_DENIED;
        rejected->status = rej;
        if (rej == GP_RPC_RPC_MISMATCH) {
            rejected->gp_rpc_rejected_reply_u.mismatch_info.high = 2;
            rejected->gp_rpc_rejected_reply_u.mismatch_info.low = 2;
        } else {
            rejected->gp_rpc_rejected_reply_u.status = GP_RPC_AUTH_FAILED;
        }
        break;
    case EINVAL:
        rhdr->status = GP_RPC_MSG_ACCEPTED;
        accepted->reply_data.status = acc;
        if (acc == GP_RPC_PROG_MISMATCH) {
            accepted->reply_data.gp_rpc_reply_union_u.mismatch_info.high = GSSPROXYVERS;
            accepted->reply_data.gp_rpc_reply_union_u.mismatch_info.low = GSSPROXYVERS;
        }
        break;
    case 0:
        rhdr->status = GP_RPC_MSG_ACCEPTED;
        accepted->reply_data.status = GP_RPC_SUCCESS;
        break;
    default:
        rhdr->status = GP_RPC_MSG_ACCEPTED;
        accepted->reply_data.status = GP_RPC_SYSTEM_ERR;
        break;
    }

    /* always reset xdr_ctx position, as this function may be called
     * multiple times in case errors occurred after the initial header
     * was created */
    xdr_setpos(&reply->xdr_ctx, 0);

    encoded = xdr_gp_rpc_msg(&reply->xdr_ctx, &reply->msg);
    if (!encoded) {
        return EFAULT;
    }

    return 0;
}

static int gp_rpc_encode_reply(struct gp_rpc_reply *reply,
                               uint32_t xid, uint32_t proc,
                               union gp_rpc_res *res, int err,
                               gp_rpc_accept_status acc,
                               gp_rpc_reject_status rej)
{
    bool xdrok;
    int ret;

    ret = gp_rpc_encode_reply_header(reply, xid, err, acc, rej);
    if (ret != 0  || err != 0) {
        return ret;
    }

    xdrok = gp_xdr_set[proc].res_fn(&reply->xdr_ctx, (char *)res);

    if (!xdrok) {
        return gp_rpc_encode_reply_header(reply, xid, EINVAL,
                                          GP_RPC_SYSTEM_ERR, 0);
    }

    return 0;
}

static int gp_rpc_execute(struct gssproxy_ctx *gpctx, uint32_t proc,
                          union gp_rpc_arg *arg, union gp_rpc_res *res)
{
    return gp_xdr_set[proc].exec_fn(gpctx, arg, res);
}

static int gp_rpc_return_buffer(struct gp_rpc_reply *reply,
                                uint8_t **outbuf, size_t *outlen)
{
    unsigned int length;
    uint8_t *buffer;

    length = xdr_getpos(&reply->xdr_ctx);

    buffer = malloc(length);
    if (!buffer) {
        return ENOMEM;
    }
    memcpy(buffer, reply->buffer, length);

    *outbuf = buffer;
    *outlen = length;
    return 0;
}

static void gp_rpc_free_xdrs(struct gp_rpc_call *call,
                             struct gp_rpc_reply *reply,
                             int proc,
                             union gp_rpc_arg *arg,
                             union gp_rpc_res *res)
{

    xdr_free(gp_xdr_set[proc].arg_fn, (char *)arg);
    xdr_free(gp_xdr_set[proc].res_fn, (char *)res);
    xdr_destroy(&call->xdr_ctx);
    xdr_destroy(&reply->xdr_ctx);
}

int gp_rpc_process_call(struct gssproxy_ctx *gpctx,
                        uint8_t *inbuf, size_t inlen,
                        uint8_t **outbuf, size_t *outlen)
{
    struct gp_rpc_call call;
    struct gp_rpc_reply reply;
    gp_rpc_accept_status acc = 0;
    gp_rpc_reject_status rej = 0;
    union gp_rpc_arg arg;
    union gp_rpc_res res;
    uint32_t xid = 0;
    uint32_t proc;
    int ret;

    memset(&arg, 0, sizeof(union gp_rpc_arg));
    memset(&res, 0, sizeof(union gp_rpc_res));
    proc = 0;

    xdrmem_create(&call.xdr_ctx, (caddr_t)inbuf, inlen, XDR_DECODE);
    xdrmem_create(&reply.xdr_ctx, reply.buffer, MAX_RPC_SIZE, XDR_ENCODE);

    /* decode request */
    ret = gp_rpc_decode_call(&call, &xid, &proc, &arg, &acc, &rej);
    if (!ret) {
        /* execute request */
        ret = gp_rpc_execute(gpctx, proc, &arg, &res);
        if (ret) {
            acc = GP_RPC_SYSTEM_ERR;
            ret = EINVAL;
        }
    }

    /* encode reply */
    ret = gp_rpc_encode_reply(&reply, xid, proc, &res, ret, acc, rej);
    if (ret == 0) {
        /* return encoded buffer */
        ret = gp_rpc_return_buffer(&reply, outbuf, outlen);
    }
    /* free resources */
    gp_rpc_free_xdrs(&call, &reply, proc, &arg, &res);
    return ret;
}

int gp_indicate_mechs(gp_exec_std_args)
{
    return 0;
}
int gp_get_call_context(gp_exec_std_args)
{
    return 0;
}
int gp_import_and_canon_name(gp_exec_std_args)
{
    return 0;
}
int gp_export_cred(gp_exec_std_args)
{
    return 0;
}
int gp_import_cred(gp_exec_std_args)
{
    return 0;
}
int gp_acquire_cred(gp_exec_std_args)
{
    return 0;
}
int gp_store_cred(gp_exec_std_args)
{
    return 0;
}
int gp_init_sec_context(gp_exec_std_args)
{
    return 0;
}
int gp_accept_sec_context(gp_exec_std_args)
{
    return 0;
}
int gp_release_handle(gp_exec_std_args)
{
    return 0;
}
int gp_get_mic(gp_exec_std_args)
{
    return 0;
}
int gp_verify(gp_exec_std_args)
{
    return 0;
}
int gp_wrap(gp_exec_std_args)
{
    return 0;
}
int gp_unwrap(gp_exec_std_args)
{
    return 0;
}
int gp_wrap_size_limit(gp_exec_std_args)
{
    return 0;
}
