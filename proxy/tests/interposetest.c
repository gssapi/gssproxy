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
#include <sys/wait.h>
#include <errno.h>
#include <netinet/in.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include "src/gp_debug.h"
#include "src/gp_log.h"
#include "popt.h"
#include <libintl.h>

#define MAX_RPC_SIZE 1024*1024
#define _(STRING) gettext(STRING)

static const char *actor = "<not set>";

#define DEBUG(...) do { \
    char msg[4096]; \
    snprintf(msg, 4096, __VA_ARGS__); \
    fprintf(stderr, "%s line %d: %s", actor, __LINE__, msg); \
    fflush(stderr); \
} while(0);

static int gp_send_buffer(int fd, char *buf, uint32_t len)
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

static int gp_recv_buffer(int fd, char *buf, uint32_t *len)
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

static int gptest_inq_context(gss_ctx_id_t ctx)
{
    gss_name_t targ_name = GSS_C_NO_NAME;
    gss_name_t src_name = GSS_C_NO_NAME;
    OM_uint32 lifetime_rec = -1;
    OM_uint32 ctx_flags = -1;
    gss_OID mech_type = GSS_C_NO_OID;
    int locally_initiated = -1;
    int open = -1;
    gss_buffer_desc sname = {0};
    gss_buffer_desc tname = {0};
    gss_buffer_desc mechstr = {0};
    OM_uint32 time_rec = -1;
    OM_uint32 maj, min;

    maj = gss_inquire_context(&min, ctx, &src_name, &targ_name,
                              &lifetime_rec, &mech_type, &ctx_flags,
                              &locally_initiated, &open);
    if (maj == GSS_S_COMPLETE) {
        gss_OID type = GSS_C_NO_OID;
        maj = gss_display_name(&min, src_name, &sname, &type);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
        maj = gss_display_name(&min, targ_name, &tname, &type);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
        maj = gss_oid_to_str(&min, mech_type, &mechstr);
        if (maj != GSS_S_COMPLETE) {
            goto done;
        }
        DEBUG("Context properties: "
              "[ s:%s, t:%s, m:%s, l:%d, f:%d, i:%d, o:%d ]\n",
              (char *)sname.value, (char *)tname.value, (char *)mechstr.value,
              (int)lifetime_rec, (int)ctx_flags, locally_initiated, open);
    }

    maj = gss_context_time(&min, ctx, &time_rec);
    if (maj) {
        DEBUG("gss_context_time failed\n");
        gp_log_failure(GSS_C_NO_OID, maj, min);
        goto done;
    }
    DEBUG("Context validity: %d sec.\n", time_rec);

done:
    (void)gss_release_buffer(&min, &sname);
    (void)gss_release_buffer(&min, &tname);
    (void)gss_release_buffer(&min, &mechstr);
    return maj;
}

#define PROXY_LOCAL_ONLY 0
#define PROXY_LOCAL_FIRST 1
#define PROXY_REMOTE_FIRST 2
#define PROXY_REMOTE_ONLY 3

#define GSSPROXY_BEHAVIOR_ENV "GSSPROXY_BEHAVIOR"

static const char *lookup_gssproxy_behavior(int proxy_mode)
{
    switch(proxy_mode) {
    case PROXY_LOCAL_ONLY:
        return "LOCAL_ONLY";
    case PROXY_LOCAL_FIRST:
        return "LOCAL_FIRST";
    case PROXY_REMOTE_FIRST:
        return "REMOTE_FIRST";
    case PROXY_REMOTE_ONLY:
        return "REMOTE_ONLY";
    default:
        break;
    }

    return NULL;
}

static int setup_gssproxy_behavior(int proxy_mode)
{
    const char *env;

    if (getenv(GSSPROXY_BEHAVIOR_ENV)) {
        return 0;
    }

    env = lookup_gssproxy_behavior(proxy_mode);
    if (env == NULL) {
        return -1;
    }

    return setenv(GSSPROXY_BEHAVIOR_ENV, env, 0);
}

struct aproc {
    int proxy_type;
    int *cli_pipe;
    int *srv_pipe;
    char *target;
};

void run_client(struct aproc *data)
{
    uint32_t ret_maj;
    uint32_t ret_min;
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_buffer_desc target_buf;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_name_t name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t cred_handle = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc msg_buf = GSS_C_EMPTY_BUFFER;
    char *message = "SECRET";
    int ret = -1;
    gss_iov_buffer_desc iov[2] = { { 0, { 0, NULL } }, { 0, { 0, NULL } } };
    int sealed;
    uint32_t max_size = 0;

    ret = setup_gssproxy_behavior(data->proxy_type);
    if (ret) {
        goto done;
    }

    DEBUG("%s behavior: %s\n", actor, getenv(GSSPROXY_BEHAVIOR_ENV));

    target_buf.value = (void *)data->target;
    target_buf.length = strlen(data->target) + 1;

    ret_maj = gss_import_name(&ret_min, &target_buf,
                              GSS_C_NT_HOSTBASED_SERVICE, &name);
    if (ret_maj) {
        DEBUG("gss_import_name failed\n");
        goto done;
    }

    do {
        ret_maj = gss_init_sec_context(&ret_min,
                                       cred_handle,
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
        if (ret_maj != GSS_S_COMPLETE &&
            ret_maj != GSS_S_CONTINUE_NEEDED) {
            DEBUG("gss_init_sec_context() failed with: %d\n", ret_maj);
            gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
            goto done;
        }
        if (out_token.length != 0) {
            /* send to server */
            ret = gp_send_buffer(data->srv_pipe[1],
                                 out_token.value, out_token.length);
            if (ret) {
                DEBUG("Failed to send data to server!\n");
                goto done;
            }

            gss_release_buffer(&ret_min, &out_token);
        }

        if (!ctx) {
            DEBUG("No context!\n");
            goto done;
        }

        if (ret_maj == GSS_S_CONTINUE_NEEDED) {
            /* and wait for reply */
            ret = gp_recv_buffer(data->cli_pipe[0], buffer, &buflen);
            if (ret) {
                DEBUG("Failed to receive data from server!\n");
                goto done;
            }

            in_token.value = buffer;
            in_token.length = buflen;
        }

    } while (ret_maj == GSS_S_CONTINUE_NEEDED);

    ret = gptest_inq_context(ctx);
    if (ret) {
        DEBUG("Failed to inquire context!\n");
        goto done;
    }

    /* test gss_wrap_size_limit */

    ret_maj = gss_wrap_size_limit(&ret_min,
                                  ctx,
                                  1, /* conf_req */
                                  GSS_C_QOP_DEFAULT, /* qop_req */
                                  4096, /* size_req */
                                  &max_size);
    if (ret_maj) {
        DEBUG("gss_wrap_size_limit failed.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }


    /* test encryption */
    msg_buf.length = strlen(message) + 1;
    msg_buf.value = (void *)message;
    ret_maj = gss_wrap(&ret_min, ctx, 1, 0, &msg_buf, NULL, &out_token);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to wrap message.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_send_buffer(data->srv_pipe[1], out_token.value, out_token.length);
    if (ret) {
        DEBUG("Failed to send data to server!\n");
        goto done;
    }

    gss_release_buffer(&ret_min, &out_token);

    ret = gp_recv_buffer(data->cli_pipe[0], buffer, &buflen);
    if (ret) {
        DEBUG("Failed to receive data from server!\n");
        goto done;
    }
    msg_buf.value = (void *)buffer;
    msg_buf.length = buflen;
    buffer[buflen] = '\0';

    in_token.value = (void *)&buffer[buflen + 1];
    ret = gp_recv_buffer(data->cli_pipe[0], in_token.value, &buflen);
    if (ret) {
        DEBUG("Failed to receive data from server!\n");
        goto done;
    }
    in_token.length = buflen;

    ret_maj = gss_verify_mic(&ret_min, ctx, &msg_buf, &in_token, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to verify message (%s).\n", buffer);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    fprintf(stdout, "Client, RECV: [%s]\n", buffer);

    /* test gss_wrap_iov_length */

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = NULL;
    iov[0].buffer.length = 0;

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].buffer.value = NULL;
    iov[1].buffer.length = msg_buf.length;

    ret_maj = gss_wrap_iov_length(&ret_min,
                                  ctx,
                                  1, /* seal */
                                  GSS_C_QOP_DEFAULT,
                                  &sealed,
                                  iov,
                                  2);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_wrap_iov_length failed\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    buflen = iov[0].buffer.length;

    /* test gss_wrap_iov */

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.length = buflen;
    iov[0].buffer.value = malloc(iov[0].buffer.length);
    if (!iov[0].buffer.value) {
        DEBUG("Out of memory\n");
        goto done;
    }

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].buffer.value = msg_buf.value;
    iov[1].buffer.length = msg_buf.length;

    ret_maj = gss_wrap_iov(&ret_min,
                           ctx,
                           1, /* seal */
                           GSS_C_QOP_DEFAULT,
                           &sealed,
                           iov,
                           2);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_wrap_iov failed.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_send_buffer(data->srv_pipe[1], iov[0].buffer.value, iov[0].buffer.length);
    if (ret) {
        DEBUG("Failed to send data to server!\n");
        goto done;
    }

    ret = gp_send_buffer(data->srv_pipe[1], iov[1].buffer.value, iov[1].buffer.length);
    if (ret) {
        DEBUG("Failed to send data to server!\n");
        goto done;
    }

    ret_maj = gss_delete_sec_context(&ret_min, &ctx, &out_token);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to delete context!\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_send_buffer(data->srv_pipe[1], out_token.value, out_token.length);
    if (ret) {
        DEBUG("Failed to send data to server!\n");
        goto done;
    }

    gss_release_buffer(&ret_min, &out_token);

    DEBUG("Success!\n");

done:
    free(iov[0].buffer.value);
    gss_release_name(&ret_min, &name);
    gss_release_buffer(&ret_min, &out_token);
    close(data->cli_pipe[0]);
    close(data->srv_pipe[1]);
    exit(ret);
}

void run_server(struct aproc *data)
{
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
    gss_buffer_desc const_buf;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_name_t canon_name = GSS_C_NO_NAME;
    gss_buffer_desc out_name_buf = GSS_C_EMPTY_BUFFER;
    gss_OID out_name_type = GSS_C_NO_OID;
    gss_buffer_desc exported_name = GSS_C_EMPTY_BUFFER;
    const char *message = "This message is authentic!";
    int ret = -1;
    gss_iov_buffer_desc iov[2];
    int sealed;

    ret = setup_gssproxy_behavior(data->proxy_type);
    if (ret) {
        goto done;
    }

    DEBUG("%s behavior: %s\n", actor, getenv(GSSPROXY_BEHAVIOR_ENV));

    const_buf.value = (void *)data->target;
    const_buf.length = strlen(data->target) + 1;

    /* import name family functions tests */
    ret_maj = gss_import_name(&ret_min, &const_buf,
                              GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_canonicalize_name(&ret_min, target_name,
                                    gss_mech_krb5, &canon_name);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret_maj = gss_export_name(&ret_min, canon_name,
                              &exported_name);
    if (ret_maj) {
        DEBUG("gss_export_name() failed with: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
#if 0
    /* disabled until gss_export_name_composite server-side is fixed */
    gss_release_buffer(&ret_min, &exported_name);

    ret_maj = gss_export_name_composite(&ret_min, canon_name,
                                        &exported_name);
    if (ret_maj) {
        DEBUG("gss_export_name_composite() failed with: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
#endif
    ret_maj = gss_display_name(&ret_min, canon_name,
                               &out_name_buf, &out_name_type);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    fprintf(stdout, "Acquiring for: %s\n", (char *)out_name_buf.value);

    /* indicate mechs family functions tests */
    ret_maj = gss_indicate_mechs(&ret_min, &mech_set);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret_maj = gss_inquire_names_for_mech(&ret_min,
                                         &mech_set->elements[0],
                                         &mech_names);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_inquire_attrs_for_mech(&ret_min,
                                         &mech_set->elements[0],
                                         &mech_attrs,
                                         &known_mech_attrs);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_inquire_saslname_for_mech(&ret_min,
                                            &mech_set->elements[0],
                                            &sasl_mech_name,
                                            &mech_name,
                                            &mech_description);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(&mech_set->elements[0], ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_display_mech_attr(&ret_min,
                                    &mech_attrs->elements[0],
                                    &name, &short_desc, &long_desc);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_indicate_mechs_by_attrs(&ret_min,
                                          GSS_C_NO_OID_SET,
                                          GSS_C_NO_OID_SET,
                                          GSS_C_NO_OID_SET,
                                          &mechs);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    ret_maj = gss_inquire_mechs_for_name(&ret_min, target_name, &mech_types);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret_maj = gss_acquire_cred(&ret_min,
                               GSS_C_NO_NAME,
                               GSS_C_INDEFINITE,
                               mech_set,
                               GSS_C_ACCEPT,
                               &cred_handle,
                               NULL,
                               NULL);
    if (ret_maj) {
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        DEBUG("Failed to get data from client!\n");
        goto done;
    }

    in_token.value = buffer;
    in_token.length = buflen;

    ret_maj = gss_accept_sec_context(&ret_min,
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
        DEBUG("gssproxy returned an error: %d\n", ret_maj);
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    if (out_token.length) {
        ret = gp_send_buffer(data->cli_pipe[1],
                             out_token.value, out_token.length);
        if (ret) {
            DEBUG("Failed to send data to client!\n");
            goto done;
        }
    }

    gss_release_buffer(&ret_min, &out_token);

    ret = gptest_inq_context(context_handle);
    if (ret) {
        DEBUG("Failed to inquire context!\n");
        goto done;
    }

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        DEBUG("Failed to get data from client!\n");
        goto done;
    }
    in_token.value = buffer;
    in_token.length = buflen;

    ret_maj = gss_unwrap(&ret_min, context_handle,
                         &in_token, &out_token, NULL, NULL);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to unwrap message.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    fprintf(stdout, "Server, RECV: %s\n", (char *)out_token.value);

    gss_release_buffer(&ret_min, &out_token);

    in_token.value = message;
    in_token.length = strlen(message);

    ret_maj = gss_get_mic(&ret_min, context_handle, 0, &in_token, &out_token);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to protect message.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_send_buffer(data->cli_pipe[1], in_token.value, in_token.length);
    if (ret) {
        DEBUG("Failed to send data to client!\n");
        goto done;
    }
    ret = gp_send_buffer(data->cli_pipe[1], out_token.value, out_token.length);
    if (ret) {
        DEBUG("Failed to send data to client!\n");
        goto done;
    }

    gss_release_buffer(&ret_min, &out_token);

    /* test gss_unwrap_iov */

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        DEBUG("Failed to get data from client!\n");
        goto done;
    }

    iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
    iov[0].buffer.value = buffer;
    iov[0].buffer.length = buflen;

    ret = gp_recv_buffer(data->srv_pipe[0], buffer+buflen, &buflen);
    if (ret) {
        DEBUG("Failed to get data from client!\n");
        goto done;
    }

    iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
    iov[1].buffer.value = buffer+iov[0].buffer.length;
    iov[1].buffer.length = buflen;

    ret_maj = gss_unwrap_iov(&ret_min,
                             context_handle,
                             &sealed,
                             NULL, /* qop_state */
                             iov,
                             2);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("gss_unwrap_iov failed\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }

    ret = gp_recv_buffer(data->srv_pipe[0], buffer, &buflen);
    if (ret) {
        DEBUG("Failed to get data from client!\n");
        goto done;
    }
    const_buf.value = buffer;
    const_buf.length = buflen;

    ret_maj = gss_process_context_token(&ret_min, context_handle, &const_buf);
    if (ret_maj != GSS_S_COMPLETE) {
        DEBUG("Failed to process context token.\n");
        gp_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        goto done;
    }
    /* The follwing will cause the context to leak, but it is unavoidable until
     * gss_process_context_token() is fixed to at least NULL the internal
     * context in the union context. */
    context_handle = GSS_C_NO_CONTEXT;

    DEBUG("Success!\n");

done:
    gss_release_name(&ret_min, &src_name);
    gss_release_buffer(&ret_min, &out_token);
    gss_release_cred(&ret_min, &deleg_cred);
    gss_delete_sec_context(&ret_min, &context_handle, GSS_C_NO_BUFFER);
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
    gss_release_name(&ret_min, &target_name);
    gss_release_name(&ret_min, &canon_name);
    gss_release_buffer(&ret_min, &out_name_buf);
    gss_release_oid(&ret_min, &out_name_type);
    gss_release_buffer(&ret_min, &exported_name);
    close(data->srv_pipe[0]);
    close(data->cli_pipe[1]);
    exit(ret);
}

static int run_cli_srv_test(int server_proxy_type,
                            int client_proxy_type,
                            char *target)
{
    int srv_pipe[2];
    int cli_pipe[2];
    struct aproc client, server;
    pid_t cli, srv, w;
    int closewait;
    int options;
    int status;
    int ret;

    ret = pipe(srv_pipe);
    if (ret) {
        return -1;
    }
    ret = pipe(cli_pipe);
    if (ret) {
        return -1;
    }

    srv = -1;
    cli = -1;

    server.proxy_type = server_proxy_type;
    server.srv_pipe = srv_pipe;
    server.cli_pipe = cli_pipe;
    server.target = target;

    srv = fork();
    switch (srv) {
    case -1:
        ret = -1;
        goto done;
    case 0:
        actor = "SERVER";
        run_server(&server);
        exit(0);
    default:
        close(srv_pipe[0]);
        close(cli_pipe[1]);
        break;
    }

    client.proxy_type = client_proxy_type;
    client.srv_pipe = srv_pipe;
    client.cli_pipe = cli_pipe;
    client.target = target;

    cli = fork();
    switch (cli) {
    case -1:
        ret = -1;
        goto done;
    case 0:
        actor = "CLIENT";
        run_client(&client);
        exit(0);
    default:
        close(srv_pipe[1]);
        close(cli_pipe[0]);
        break;
    }

    closewait = -1;
    while (cli != -1 || srv != -1) {
        if (closewait < 0) {
            options = 0;
        } else {
            options = WNOHANG;
        }
        w = waitpid(-1, &status, options);
        if (w == cli) {
            cli = -1;
        } else if (w == srv) {
            srv = -1;
        } else {
            /* ? */
            ret = -1;
            goto done;
        }
        /* wait 0.1s for max ten times for the other process to terminate,
         * then just exit */
        if (closewait > 10) {
            ret = -1;
            goto done;
        }

        usleep(100000);
        closewait++;
    }
    ret = 0;

done:
    if (cli > 0) {
        kill(cli, SIGKILL);
    }
    if (srv > 0) {
        kill(srv, SIGKILL);
    }
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int opt_version = 0;
    int opt_all = 0;
    char *opt_target = NULL;
    int ret, i, k;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"target", 't', POPT_ARG_STRING, &opt_target, 0, \
         _("Specify the target name used for the tests"), NULL}, \
        {"version", '\0', POPT_ARG_NONE, &opt_version, 0, \
         _("Print version number and exit"), NULL }, \
        {"all", '\0', POPT_ARG_NONE, &opt_all, 0, \
         _("Test all gssproxy modes"), NULL }, \
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

    if (!opt_all) {
            return run_cli_srv_test(PROXY_LOCAL_ONLY,
                                    PROXY_LOCAL_ONLY,
                                    opt_target);
    }

    for (i=0; i<4; i++) {
        for (k=0; k<4; k++) {
            ret = run_cli_srv_test(i, k, opt_target);
            fprintf(stderr, "Running test with server proxy mode %s "
                    "and client proxy mode %s %s\n",
                    lookup_gssproxy_behavior(i),
                    lookup_gssproxy_behavior(k),
                    ret ? "failed" : "succeeded");
            if (ret) {
                return ret;
            }
        }
    }

    return ret;
}
