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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <netinet/in.h>
#include <gssapi/gssapi.h>
#include "src/gp_utils.h"
#include "src/gp_rpc_process.h"
#include "src/gp_conv.h"
#include "popt.h"

int connect_unix_socket(const char *file_name)
{
    struct sockaddr_un addr = {0};
    int ret = 0;
    int fd = -1;

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, file_name, sizeof(addr.sun_path)-1);
    addr.sun_path[sizeof(addr.sun_path)-1] = '\0';

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        ret = errno;
        goto done;
    }

    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));

done:
    if (ret) {
        fprintf(stderr, "Failed to create Unix Socket! (%d:%s)",
               ret, strerror(ret));
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
    }
    return fd;
}

int client_init_context(char *target, gss_buffer_desc *out_token)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_buffer_desc target_buf;
    gss_name_t name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    int ret = 0;

    target_buf.value = (void *)target;
    target_buf.length = strlen(target) + 1;

    ret_maj = gss_import_name(&ret_min, &target_buf,
                              GSS_C_NT_HOSTBASED_SERVICE, &name);
    if (ret_maj) {
        goto done;
    }

    /* rely on kerberos not requiring more than one pass, so do not loop */
    ret_maj = gss_init_sec_context(&ret_min,
                                   GSS_C_NO_CREDENTIAL,
                                   &ctx,
                                   name,
                                   GSS_C_NO_OID,
                                   GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                   0,
                                   GSS_C_NO_CHANNEL_BINDINGS,
                                   NULL,
                                   NULL,
                                   out_token,
                                   NULL,
                                   NULL);
    if (ret_maj != GSS_S_CONTINUE_NEEDED) {
        ret = -1;
        goto done;
    }
    if (!ctx) {
        ret = -1;
        goto done;
    }

done:
    gss_release_name(&ret_min, &name);
    if (ret) {
        return -1;
    }
    return 0;
}

int gp_send_buffer(int fd, char *buf, uint32_t len)
{
    uint32_t size;
    size_t wn;
    size_t pos;

    size = htonl(len);

    wn = write(fd, &size, sizeof(uint32_t));
    if (wn != 4) {
        return EIO;
    }

    pos = 0;
    while (len > pos) {
        wn = write(fd, buf + pos, len - pos);
        if (wn == -1) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        pos += wn;
    }

    return 0;
}

int gp_recv_buffer(int fd, char *buf, uint32_t *len)
{
    uint32_t size;
    size_t rn;
    size_t pos;

    rn = read(fd, &size, sizeof(uint32_t));
    if (rn != 4) {
        return EIO;
    }

    *len = ntohl(size);

    pos = 0;
    while (*len > pos) {
        rn = read(fd, buf + pos, *len - pos);
        if (rn == -1) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        if (rn == 0) {
            return EIO;
        }
        pos += rn;
    }

    return 0;
}

int gp_prep_accept_sec_context(gss_buffer_t in_token,
                               gssx_arg_accept_sec_context *args)
{
    return gp_conv_buffer_to_gssx(in_token, &args->input_token);
}

int gp_send_accept_sec_context(int fd,
                               gssx_arg_accept_sec_context *arg,
                               gssx_res_accept_sec_context *res)
{
    XDR xdr_call_ctx;
    XDR xdr_reply_ctx;
    gp_rpc_msg msg;
    char buffer[MAX_RPC_SIZE];
    uint32_t length;
    bool xdrok;
    int ret;

    memset(&msg, 0, sizeof(gp_rpc_msg));

    xdrmem_create(&xdr_call_ctx, buffer, MAX_RPC_SIZE, XDR_ENCODE);
    xdrmem_create(&xdr_reply_ctx, buffer, MAX_RPC_SIZE, XDR_DECODE);

    msg.xid = 1;
    msg.header.type = GP_RPC_CALL;
    msg.header.gp_rpc_msg_union_u.chdr.rpcvers = 2;
    msg.header.gp_rpc_msg_union_u.chdr.prog = GSSPROXY;
    msg.header.gp_rpc_msg_union_u.chdr.vers = GSSPROXYVERS;
    msg.header.gp_rpc_msg_union_u.chdr.proc = GSSX_ACCEPT_SEC_CONTEXT;
    msg.header.gp_rpc_msg_union_u.chdr.cred.flavor = GP_RPC_AUTH_NONE;
    msg.header.gp_rpc_msg_union_u.chdr.cred.body.body_len = 0;
    msg.header.gp_rpc_msg_union_u.chdr.cred.body.body_val = NULL;
    msg.header.gp_rpc_msg_union_u.chdr.verf.flavor = GP_RPC_AUTH_NONE;
    msg.header.gp_rpc_msg_union_u.chdr.verf.body.body_len = 0;
    msg.header.gp_rpc_msg_union_u.chdr.verf.body.body_val = NULL;

    /* encode header */
    xdrok = xdr_gp_rpc_msg(&xdr_call_ctx, &msg);
    if (!xdrok) {
        return EFAULT;
    }

    /* encode data */
    xdrok = xdr_gssx_arg_accept_sec_context(&xdr_call_ctx, arg);
    if (!xdrok) {
        return EFAULT;
    }

    /* send to proxy */
    ret = gp_send_buffer(fd, buffer, xdr_getpos(&xdr_call_ctx));
    if (ret) {
        return EIO;
    }

    /* receive answer */
    ret = gp_recv_buffer(fd, buffer, &length);
    if (ret) {
        return EIO;
    }

    /* decode header */
    xdrok = xdr_gp_rpc_msg(&xdr_reply_ctx, &msg);
    if (!xdrok) {
        return EFAULT;
    }

    if (msg.xid != 1 ||
        msg.header.type != GP_RPC_REPLY ||
        msg.header.gp_rpc_msg_union_u.rhdr.status != GP_RPC_MSG_ACCEPTED ||
        msg.header.gp_rpc_msg_union_u.rhdr.gp_rpc_reply_header_u.accepted.reply_data.status != GP_RPC_SUCCESS) {
        return EINVAL;
    }

    /* decode answer */
    xdrok = xdr_gssx_res_accept_sec_context(&xdr_reply_ctx, res);
    if (!xdrok) {
        return EFAULT;
    }

    xdr_free((xdrproc_t)xdr_gp_rpc_msg, (char *)&msg);
    xdr_destroy(&xdr_call_ctx);
    xdr_destroy(&xdr_reply_ctx);
    return 0;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_version = 0;
    struct gp_config *cfg;
    char *opt_config_file = NULL;
    char *opt_target = NULL;
    int fd;
    int ret;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gssx_arg_accept_sec_context arg;
    gssx_res_accept_sec_context res;
    uint32_t ret_min;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"config", 'c', POPT_ARG_STRING, &opt_config_file, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"target", 't', POPT_ARG_STRING, &opt_target, 0, \
         _("Specify a non-default config file"), NULL}, \
        {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
         _("Print version number and exit"), NULL }, \
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    if (opt_version) {
        puts(VERSION""DISTRO_VERSION""PRERELEASE_VERSION);
        return 0;
    }

    cfg = read_config(opt_config_file, 0);
    if (!cfg) {
        return -1;
    }

    memset(&arg, 0, sizeof(gssx_arg_accept_sec_context));
    memset(&res, 0, sizeof(gssx_res_accept_sec_context));

    /* connect to the socket first to make sure the proxy is available */
    fd = connect_unix_socket(cfg->socket_name);
    if (fd == -1) {
        return -1;
    }

    ret = client_init_context(opt_target, &out_token);
    if (ret) {
        return -1;
    }

    ret = gp_prep_accept_sec_context(&out_token, &arg);
    if (ret) {
        return -1;
    }

    ret = gp_send_accept_sec_context(fd, &arg, &res);
    if (ret) {
        return -1;
    }

    if (res.status.major_status) {
        return -1;
    }

    xdr_free((xdrproc_t)xdr_gssx_arg_accept_sec_context, (char *)&arg);
    xdr_free((xdrproc_t)xdr_gssx_res_accept_sec_context, (char *)&res);
    gss_release_buffer(&ret_min, &out_token);
    return 0;
}

