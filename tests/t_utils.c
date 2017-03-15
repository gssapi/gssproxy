/* Copyright (C) 2014 the GSS-PROXY contributors, see COPYING for license */

#include "t_utils.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

int t_send_buffer(int fd, char *buf, uint32_t len)
{
    uint32_t size;
    ssize_t wn;
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

int t_recv_buffer(int fd, char *buf, uint32_t *len)
{
    uint32_t size;
    ssize_t rn;
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

void t_log_failure(gss_OID mech, uint32_t maj, uint32_t min)
{
    uint32_t msgctx;
    uint32_t discard;
    gss_buffer_desc tmp;

    fprintf(stderr, "Failed with:");

    if (mech != GSS_C_NO_OID) {
        gss_oid_to_str(&discard, mech, &tmp);
        fprintf(stderr, " (OID: %s)", (char *)tmp.value);
        gss_release_buffer(&discard, &tmp);
    }

    msgctx = 0;
    gss_display_status(&discard, maj, GSS_C_GSS_CODE, mech, &msgctx, &tmp);
    fprintf(stderr, " %s,", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);

    msgctx = 0;
    gss_display_status(&discard, min, GSS_C_MECH_CODE, mech, &msgctx, &tmp);
    fprintf(stderr, " %s\n", (char *)tmp.value);
    gss_release_buffer(&discard, &tmp);
}

int t_string_to_name(const char *string, gss_name_t *name, gss_OID type)
{
    gss_buffer_desc target_buf;
    uint32_t ret_maj;
    uint32_t ret_min;

    target_buf.value = strdup(string);
    target_buf.length = strlen(string) + 1;

    ret_maj = gss_import_name(&ret_min, &target_buf, type, name);
    free(target_buf.value);
    return ret_maj;
}
