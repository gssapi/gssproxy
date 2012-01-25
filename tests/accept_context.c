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
#include <pthread.h>
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

    if (*len > MAX_RPC_SIZE) {
        return EINVAL;
    }

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

struct athread {
    pthread_t tid;
    int *cli_pipe;
    int *srv_pipe;
    struct gp_config *cfg;
    char *target;
};

void *client_thread(void *pvt)
{
    struct athread *data;
    uint32_t ret_maj;
    uint32_t ret_min;
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_buffer_desc target_buf;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_name_t name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    int ret = 0;

    data = (struct athread *)pvt;

    target_buf.value = (void *)data->target;
    target_buf.length = strlen(data->target) + 1;

    ret_maj = gss_import_name(&ret_min, &target_buf,
                              GSS_C_NT_HOSTBASED_SERVICE, &name);
    if (ret_maj) {
        goto done;
    }

    do {
        ret_maj = gss_init_sec_context(&ret_min,
                                       GSS_C_NO_CREDENTIAL,
                                       &ctx,
                                       name,
                                       GSS_C_NO_OID,
                                       GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &in_token,
                                       NULL,
                                       &out_token,
                                       NULL,
                                       NULL);
        if (ret_maj == GSS_S_COMPLETE) {
            break;
        }
        if (ret_maj != GSS_S_CONTINUE_NEEDED) {
            fprintf(stdout,
                    "gss_init_sec_context() failed with: %d\n", ret_maj);
            goto done;
        }
        if (!ctx) {
            goto done;
        }

        /* send to server */
        ret = gp_send_buffer(data->srv_pipe[1],
                             out_token.value, out_token.length);
        if (ret) {
            goto done;
        }

        gss_release_buffer(&ret_min, &out_token);

        /* and wait for reply */
        ret = gp_recv_buffer(data->cli_pipe[0], buffer, &buflen);
        if (ret) {
            goto done;
        }

        in_token.value = buffer;
        in_token.length = buflen;

    } while (ret_maj == GSS_S_CONTINUE_NEEDED);

    fprintf(stdout, "client: Success!\n");

done:
    gss_release_name(&ret_min, &name);
    gss_release_buffer(&ret_min, &out_token);
    close(data->cli_pipe[0]);
    close(data->cli_pipe[1]);
    pthread_exit(NULL);
}

void *server_thread(void *pvt)
{
    struct athread *data;
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
    gssx_arg_accept_sec_context arg;
    gssx_res_accept_sec_context res;
    int ret;
    int fd;

    data = (struct athread *)pvt;

    memset(&arg, 0, sizeof(gssx_arg_accept_sec_context));
    memset(&res, 0, sizeof(gssx_res_accept_sec_context));

    /* connect to the socket first to make sure the proxy is available */
    fd = connect_unix_socket(data->cfg->socket_name);
    if (fd == -1) {
        goto done;
    }

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        fprintf(stdout, "Failed to get data from client!\n");
        goto done;
    }

    token.value = buffer;
    token.length = buflen;

    ret = gp_conv_buffer_to_gssx(&token, &arg.input_token);
    if (ret) {
        fprintf(stderr, "gp_conv_buffer_to_gssx() failed!\n");
        goto done;
    }

    ret = gp_send_accept_sec_context(fd, &arg, &res);
    if (ret) {
        fprintf(stdout, "Comms with gssproxy failed!\n");
    }

    if (res.status.major_status) {
        fprintf(stdout, "gssproxy returned an error: %ld\n",
                        res.status.major_status);
        goto done;
    }

    gp_conv_gssx_to_buffer(res.output_token, &token);

    ret = gp_send_buffer(data->cli_pipe[1], token.value, token.length);
    if (ret) {
        fprintf(stdout, "Failed to send data to client!\n");
        goto done;
    }

done:
    xdr_free((xdrproc_t)xdr_gssx_arg_accept_sec_context, (char *)&arg);
    xdr_free((xdrproc_t)xdr_gssx_res_accept_sec_context, (char *)&res);
    close(data->srv_pipe[0]);
    close(data->srv_pipe[1]);
    pthread_exit(NULL);
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_version = 0;
    struct gp_config *cfg;
    char *opt_config_file = NULL;
    char *opt_target = NULL;
    int srv_pipe[2];
    int cli_pipe[2];
    pthread_attr_t attr;
    struct athread server;
    struct athread client;
    void *retval;
    int ret;

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

    if (opt_target == NULL) {
        fprintf(stderr, "Missing target!\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    cfg = read_config(opt_config_file, 0);
    if (!cfg) {
        return -1;
    }

    ret = pipe(srv_pipe);
    if (ret) {
        return -1;
    }
    ret = pipe(cli_pipe);
    if (ret) {
        return -1;
    }

    /* make thread joinable (portability) */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    server.srv_pipe = srv_pipe;
    server.cli_pipe = cli_pipe;
    server.cfg = cfg;
    server.target = NULL;

    ret = pthread_create(&server.tid, &attr, server_thread, &server);
    if (ret) {
        return -1;
    }

    client.srv_pipe = srv_pipe;
    client.cli_pipe = cli_pipe;
    client.cfg = cfg;
    client.target = opt_target;

    ret = pthread_create(&client.tid, &attr, client_thread, &client);
    if (ret) {
        return -1;
    }

    pthread_join(server.tid, &retval);
    pthread_join(client.tid, &retval);

    return 0;
}

