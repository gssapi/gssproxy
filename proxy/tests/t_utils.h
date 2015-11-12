/* Copyright (C) 2014 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

#define STDIN_FD 0
#define STDOUT_FD 1
#define MAX_RPC_SIZE 1024*1024

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

#define DEBUG(...) do { \
    char msg[4096]; \
    snprintf(msg, 4096, __VA_ARGS__); \
    fprintf(stderr, "%s[%s:%d]: %s", argv[0], __FUNCTION__, __LINE__, msg); \
    fflush(stderr); \
} while(0);

int t_send_buffer(int fd, char *buf, uint32_t len);
int t_recv_buffer(int fd, char *buf, uint32_t *len);

void t_log_failure(gss_OID mech, uint32_t maj, uint32_t min);

int t_string_to_name(const char *string, gss_name_t *name, gss_OID type);
