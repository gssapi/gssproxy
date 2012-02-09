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
#include <gssapi/gssapi_krb5.h>
#include "src/gp_proxy.h"
#include "src/gp_rpc_process.h"
#include "src/gp_conv.h"
#include "src/gp_debug.h"
#include "src/mechglue/gssapi_gpm.h"
#include "popt.h"

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
    close(data->srv_pipe[1]);
    pthread_exit(NULL);
}

void *server_thread(void *pvt)
{
    struct athread *data;
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    uint32_t ret_maj;
    uint32_t ret_min;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_name_t src_name;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_cred_id_t deleg_cred = GSS_C_NO_CREDENTIAL;
    gss_OID_set mech_set = GSS_C_NO_OID_SET;
    gss_OID_set mech_names = GSS_C_NO_OID_SET;
    gss_OID_set mech_types = GSS_C_NO_OID_SET;
    gss_OID_set mech_attrs = GSS_C_NO_OID_SET;
    gss_OID_set known_mech_attrs = GSS_C_NO_OID_SET;
    gss_buffer_desc sasl_mech_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mech_name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc mech_description = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc short_desc = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc long_desc = GSS_C_EMPTY_BUFFER;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc target_buf;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_name_t canon_name = GSS_C_NO_NAME;
    gss_buffer_desc out_name_buf = GSS_C_EMPTY_BUFFER;
    gss_OID out_name_type = GSS_C_NO_OID;
    int ret;

    data = (struct athread *)pvt;

    target_buf.value = (void *)data->target;
    target_buf.length = strlen(data->target) + 1;

    /* import name family functions tests */
    ret_maj = gpm_import_name(&ret_min, &target_buf,
                              GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_canonicalize_name(&ret_min, target_name,
                                    gss_mech_krb5, &canon_name);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_display_name(&ret_min, canon_name,
                               &out_name_buf, &out_name_type);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    fprintf(stdout, "Acquiring for: %s\n", (char *)out_name_buf.value);

    /* indicate mechs family functions tests */
    ret_maj = gpm_indicate_mechs(&ret_min, &mech_set);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret_maj = gpm_inquire_names_for_mech(&ret_min,
                                         &mech_set->elements[0],
                                         &mech_names);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_inquire_attrs_for_mech(&ret_min,
                                         &mech_set->elements[0],
                                         &mech_attrs,
                                         &known_mech_attrs);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_inquire_saslname_for_mech(&ret_min,
                                            &mech_set->elements[0],
                                            &sasl_mech_name,
                                            &mech_name,
                                            &mech_description);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_display_mech_attr(&ret_min,
                                    &mech_attrs->elements[0],
                                    &name, &short_desc, &long_desc);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_indicate_mechs_by_attrs(&ret_min,
                                          GSS_C_NO_OID_SET,
                                          GSS_C_NO_OID_SET,
                                          GSS_C_NO_OID_SET,
                                          &mechs);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gpm_inquire_mechs_for_name(&ret_min, target_name, &mech_types);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret_maj = gpm_acquire_cred(&ret_min,
                               GSS_C_NO_NAME,
                               GSS_C_INDEFINITE,
                               mech_set,
                               GSS_C_ACCEPT,
                               &cred_handle,
                               NULL,
                               NULL);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        fprintf(stdout, "Failed to get data from client!\n");
        goto done;
    }

    in_token.value = buffer;
    in_token.length = buflen;

    ret_maj = gpm_accept_sec_context(&ret_min,
                                     &context_handle,
                                     cred_handle,
                                     &in_token,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     &src_name,
                                     NULL,
                                     &out_token,
                                     NULL,
                                     NULL,
                                     &deleg_cred);
    if (ret_maj) {
        fprintf(stdout, "gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    if (out_token.length) {
        ret = gp_send_buffer(data->cli_pipe[1],
                             out_token.value, out_token.length);
        if (ret) {
            fprintf(stdout, "Failed to send data to client!\n");
            goto done;
        }
    }

done:
    gpm_release_name(&ret_min, &src_name);
    gpm_release_buffer(&ret_min, &out_token);
    gpm_release_cred(&ret_min, &deleg_cred);
    gpm_delete_sec_context(&ret_min, &context_handle, GSS_C_NO_BUFFER);
    gss_release_oid_set(&ret_min, &mech_set);
    gss_release_oid_set(&ret_min, &mech_names);
    gss_release_oid_set(&ret_min, &mech_types);
    gss_release_oid_set(&ret_min, &mech_attrs);
    gss_release_oid_set(&ret_min, &known_mech_attrs);
    gss_release_buffer(&ret_min, &sasl_mech_name);
    gss_release_buffer(&ret_min, &mech_name);
    gss_release_buffer(&ret_min, &mech_description);
    gss_release_buffer(&ret_min, &name);
    gss_release_buffer(&ret_min, &short_desc);
    gss_release_buffer(&ret_min, &long_desc);
    gss_release_oid_set(&ret_min, &mechs);
    gpm_release_name(&ret_min, &target_name);
    gpm_release_name(&ret_min, &canon_name);
    gss_release_buffer(&ret_min, &out_name_buf);
    gss_release_oid(&ret_min, &out_name_type);
    close(data->srv_pipe[0]);
    close(data->cli_pipe[1]);
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
    server.target = opt_target;

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

