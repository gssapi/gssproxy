/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_COMMON_H_
#define _GP_COMMON_H_

#include "config.h"
#include "gp_debug.h"
#include "gp_log.h"

#define no_const(ptr) ((void *)((uintptr_t)(ptr)))
#define UNUSED  __attribute__((unused))

/* add element to list head */
#define LIST_ADD(list, elem) do { \
    elem->prev = NULL; \
    elem->next = list; \
    if (list) { \
        list->prev = elem; \
    } \
    list = elem; \
} while (0)

/* remove element from list */
#define LIST_DEL(list, elem) do { \
    if (elem->next) { \
        elem->next->prev = elem->prev; \
    } \
    if (elem->prev) { \
        elem->prev->next = elem->next; \
    } \
    if (list == elem) { \
        list = elem->next; \
    } \
    elem->prev = NULL; \
    elem->next = NULL; \
} while (0)

#define safefree(ptr) do { \
    free(no_const(ptr)); \
    ptr = NULL; \
} while(0)

/* max out at 1MB for now */
#define MAX_RPC_SIZE 1024*1024

bool gp_same(const char *a, const char *b);
bool gp_boolean_is_true(const char *s);
char *gp_getenv(const char *name);

ssize_t gp_safe_read(int fd, void *buf, size_t count);
ssize_t gp_safe_write(int fd, const void *buf, size_t count);
/* NOTE: read the note in gp_util.c before using gp_strerror() */
char *gp_strerror(int errnum);

#include "rpcgen/gss_proxy.h"

union gp_rpc_arg {
    gssx_arg_release_handle release_handle;
    gssx_arg_indicate_mechs indicate_mechs;
    gssx_arg_import_and_canon_name import_and_canon_name;
    gssx_arg_get_call_context get_call_context;
    gssx_arg_acquire_cred acquire_cred;
    gssx_arg_export_cred export_cred;
    gssx_arg_import_cred import_cred;
    gssx_arg_store_cred store_cred;
    gssx_arg_init_sec_context init_sec_context;
    gssx_arg_accept_sec_context accept_sec_context;
    gssx_arg_get_mic get_mic;
    gssx_arg_verify_mic verify_mic;
    gssx_arg_wrap wrap;
    gssx_arg_unwrap unwrap;
    gssx_arg_wrap_size_limit wrap_size_limit;
};

union gp_rpc_res {
    gssx_res_release_handle release_handle;
    gssx_res_indicate_mechs indicate_mechs;
    gssx_res_import_and_canon_name import_and_canon_name;
    gssx_res_get_call_context get_call_context;
    gssx_res_acquire_cred acquire_cred;
    gssx_res_export_cred export_cred;
    gssx_res_import_cred import_cred;
    gssx_res_store_cred store_cred;
    gssx_res_init_sec_context init_sec_context;
    gssx_res_accept_sec_context accept_sec_context;
    gssx_res_get_mic get_mic;
    gssx_res_verify_mic verify_mic;
    gssx_res_wrap wrap;
    gssx_res_unwrap unwrap;
    gssx_res_wrap_size_limit wrap_size_limit;
};

#define gpopt_string_match(buf, val, len) \
    (len == (buf)->octet_string_len && \
     strncmp((val), (buf)->octet_string_val, \
                    (buf)->octet_string_len) == 0)

#define gp_option_name_match(opt, val, len) \
    gpopt_string_match(&((opt)->option), val, len)

#define gp_option_value_match(opt, val, len) \
    gpopt_string_match(&((opt)->value), val, len)

#define gp_options_find(res, opts, name, len) \
do { \
    struct gssx_option *_v; \
    res = NULL; \
    for (unsigned _o = 0; _o < opts.options_len; _o++) { \
        _v = &opts.options_val[_o]; \
        if (gp_option_name_match(_v, name, len)) { \
            res = _v; \
            break; \
        } \
    } \
} while(0)

#define ACQUIRE_TYPE_OPTION         "acquire_type"
#define ACQUIRE_IMPERSONATE_NAME    "impersonate_name"
#define CRED_SYNC_OPTION "sync_modified_creds"
#define CRED_SYNC_DEFAULT "default"
#define CRED_SYNC_PAYLOAD "sync_creds"

#define GPKRB_MAX_CRED_SIZE 1024 * 512

uint32_t gp_add_option(gssx_option **options_val, u_int *options_len,
                       const void *option, size_t option_len,
                       const void *value, size_t value_len);

#endif /* _GP_COMMON_H_ */
