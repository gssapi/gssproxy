/* Copyright (C) 2014 the GSS-PROXY contributors, see COPYING for license */

#include "t_utils.h"

int main(int argc, const char *argv[])
{
    char buffer[MAX_RPC_SIZE];
    uint32_t buflen;
    gss_ctx_id_t context_handle = GSS_C_NO_CONTEXT;
    gss_buffer_desc in_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc out_token = GSS_C_EMPTY_BUFFER;
    gss_name_t src_name;
    uint32_t ret_maj;
    uint32_t ret_min;
    int ret = -1;

    /* We get stuff from stdin and spit it out on stderr */
    ret = t_recv_buffer(STDIN_FD, buffer, &buflen);
    if (ret != 0) {
        DEBUG("Failed to read token from STDIN\n");
        ret = -1;
        goto done;
    }

    in_token.value = buffer;
    in_token.length = buflen;

    ret_maj = gss_accept_sec_context(&ret_min,
                                     &context_handle,
                                     GSS_C_NO_CREDENTIAL,
                                     &in_token,
                                     GSS_C_NO_CHANNEL_BINDINGS,
                                     &src_name,
                                     NULL,
                                     &out_token,
                                     NULL,
                                     NULL,
                                     NULL);
    if (ret_maj) {
        DEBUG("Error accepting context\n");
        t_log_failure(GSS_C_NO_OID, ret_maj, ret_min);
        ret = -1;
        goto done;
    }

    if (!out_token.length) {
        DEBUG("No output token ?");
        ret = -1;
        goto done;
    }

    ret = t_send_buffer(STDOUT_FD, out_token.value, out_token.length);
    if (ret) {
        DEBUG("Failed to send data to client!\n");
        ret = -1;
        goto done;
    }

    ret = 0;

done:
    gss_delete_sec_context(&ret_min, &context_handle, NULL);
    gss_release_buffer(&ret_min, &out_token);
    gss_release_name(&ret_min, &src_name);
    return ret;
}
