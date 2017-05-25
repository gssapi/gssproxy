/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_PROXY_H_
#define _GP_PROXY_H_

#include <libintl.h>
#include <stdbool.h>
#include <stdint.h>
#include <gssapi/gssapi_ext.h>
#include "verto.h"
#include "gp_common.h"
#include "gp_selinux.h"

#define _(STRING) gettext(STRING)
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

#define LINUX_PROC_USE_GSS_PROXY_FILE "/proc/net/rpc/use-gss-proxy"

#define GP_CRED_KRB5    0x01

struct gp_creds_handle;

struct gp_cred_krb5 {
    char *principal;
    gss_key_value_set_desc store;
    struct gp_creds_handle *creds_handle;
};

struct gp_service {
    char *name;
    uid_t euid;
    bool any_uid;
    bool allow_proto_trans;
    bool allow_const_deleg;
    bool allow_cc_sync;
    bool trusted;
    bool kernel_nfsd;
    bool impersonate;
    char *socket;
    SELINUX_CTX selinux_ctx;
    gss_cred_usage_t cred_usage;
    uint32_t filter_flags;
    uint32_t enforce_flags;

    uint32_t mechs;
    struct gp_cred_krb5 krb5;

    verto_ev *ev;
};

struct gp_config {
    char *config_file;      /* gssproxy configuration file */
    char *config_dir;       /* gssproxy configuration directory */
    bool daemonize;         /* let gssproxy daemonize */
    char *socket_name;      /* the socket name to use for */
    int num_workers;        /* number of worker threads */

    struct gp_service **svcs;
    int num_svcs;

    char *proxy_user;       /* user to drop privs to if not NULL */
};

struct gp_workers;

struct gssproxy_ctx {
    struct gp_config *config;
    struct gp_workers *workers;
    verto_ctx *vctx;
    verto_ev *sock_ev;      /* default socket event */
};

struct gp_sock_ctx {
    struct gssproxy_ctx *gpctx;
    const char *socket;
    int fd;
};

struct gp_conn;

struct gp_call_ctx {
    struct gssproxy_ctx *gpctx;
    struct gp_service *service;
    struct gp_conn *connection;
    void (*destroy_callback)(void *);
    void *destroy_callback_data;
};

/* from gp_config.c */
struct gp_config *read_config(char *config_file, char *config_dir,
                              char *socket_name, int opt_daemonize);
struct gp_creds_handle *gp_service_get_creds_handle(struct gp_service *svc);
void free_config(struct gp_config **config);
void free_cred_store_elements(gss_key_value_set_desc *cs);

/* from gp_init.c */
void init_server(bool daemonize, int *wait_fd);
void init_done(int wait_fd);
void fini_server(void);
verto_ctx *init_event_loop(void);
void init_proc_nfsd(struct gp_config *cfg);
void write_pid(void);
int drop_privs(struct gp_config *cfg);

/* from gp_socket.c */
void free_unix_socket(verto_ctx *ctx, verto_ev *ev);
struct gp_sock_ctx *init_unix_socket(struct gssproxy_ctx *gpctx,
                                     const char *file_name);
void accept_sock_conn(verto_ctx *vctx, verto_ev *ev);
void gp_conn_free(struct gp_conn *conn);
void gp_socket_send_data(verto_ctx *vctx, struct gp_conn *conn,
                         uint8_t *buffer, size_t buflen);
struct gp_creds *gp_conn_get_creds(struct gp_conn *conn);
uid_t gp_conn_get_uid(struct gp_conn *conn);
const char *gp_conn_get_socket(struct gp_conn *conn);
int gp_conn_get_cid(struct gp_conn *conn);
bool gp_selinux_ctx_equal(SELINUX_CTX ctx1, SELINUX_CTX ctx2);
bool gp_conn_check_selinux(struct gp_conn *conn, SELINUX_CTX ctx);

/* from gp_workers.c */
int gp_workers_init(struct gssproxy_ctx *gpctx);
void gp_workers_free(struct gp_workers *w);
int gp_query_new(struct gp_workers *w, struct gp_conn *conn,
                 uint8_t *buffer, size_t buflen);

/* from gp_rpc.c */
int gp_rpc_process_call(struct gp_call_ctx *gpcall,
                        uint8_t *inbuf, size_t inlen,
                        uint8_t **outbuf, size_t *outlen);

/* from gp_creds.c */
struct gp_service *gp_creds_match_conn(struct gssproxy_ctx *gpctx,
                                       struct gp_conn *conn);

/* from gp_export.c */
uint32_t gp_init_creds_handle(uint32_t *min, const char *svc_name,
                              const char *keytab,
                              struct gp_creds_handle **out);
void gp_free_creds_handle(struct gp_creds_handle **in);

#endif /* _GP_PROXY_H_ */
