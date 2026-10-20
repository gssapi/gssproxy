/* Copyright (C) 2026 the GSS-PROXY contributors, see COPYING for license */

/* Keytab loaders.
 *
 * A service may name a program that produces its keytab:
 *
 *   cred_store = keytab:MEMORY:<name>
 *   keytab_loader = /path/to/loader [args]
 *
 * The loader runs with a memfd as file descriptor 3 and writes a keytab in
 * the MIT file format into it.  When it exits with status 0 the keys are
 * copied into the MEMORY keytab and the memfd is closed, so the keys never
 * touch a filesystem.  A failing loader is retried with exponential backoff
 * and keeps the keys loaded before it; SIGHUP runs the loaders again.
 *
 * MEMORY keytabs are shared by name by all krb5 contexts of the process, so
 * the worker threads see the keys through the name in the service's
 * cred_store, and so do credentials exported to clients and imported back
 * later.  The name therefore never changes; the contents are replaced in
 * place.  A MEMORY keytab is destroyed when its last handle is closed, so
 * each loader keeps one open for as long as it exists.
 *
 * Removing an entry from a MEMORY keytab frees it under any thread that is
 * iterating over the keytab, so entries are removed only while no worker is
 * processing a request (gp_keytab_lock taken for writing; workers hold it
 * for reading around each request).  The main thread never blocks on it: if
 * workers are busy, new keys are added at once and the old ones are
 * removed on a later attempt.  A request thus sees the old keys, the new
 * keys, or both, and never a keytab missing a key it is about to be given.
 */

#include "config.h"

#if defined(HAVE_MEMFD_CREATE) && defined(HAVE_PIDFD_OPEN)

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gp_proxy.h"

#define GP_KT_LOADER_FD 3
#define GP_KT_LOADER_TIMEOUT (300 * 1000)   /* kill a hung loader */
#define GP_KT_RETRY_MIN (5 * 1000)          /* first retry after failure */
#define GP_KT_RETRY_MAX (600 * 1000)        /* backoff cap */
#define GP_KT_SWAP_RETRY (1000)             /* wait for idle workers */
#define GP_KT_MAX_SIZE (1024 * 1024)        /* sanity limit on output */

struct gp_keytab_loader {
    struct gp_keytab_loader *next;
    struct gssproxy_ctx *gpctx;

    char *ktname;           /* MEMORY:<name> */
    krb5_keytab kt;         /* held open: keeps the MEMORY keytab alive */
    char **argv;            /* NULL once no service uses the keytab */
    bool in_use;            /* marker while reconciling with the config */
    bool rerun;             /* run again when the current run exits */

    pid_t pid;              /* running loader, 0 if none */
    int memfd;              /* its output */
    verto_ev *child_ev;     /* pidfd readable: the loader exited */
    verto_ev *timeout_ev;   /* the loader runs too long */
    verto_ev *retry_ev;     /* next attempt after a failure */
    int backoff;            /* next retry delay, in ms */

    int keys_fd;            /* keys waiting to be installed, -1: none */
    verto_ev *swap_ev;      /* pending removal of the previous keys */
};

static pthread_rwlock_t gp_keytab_lock;
static pthread_once_t gp_keytab_lock_once = PTHREAD_ONCE_INIT;
static krb5_context gp_kt_ctx;

static void gp_keytab_lock_init(void)
{
    pthread_rwlockattr_t attr;

    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr,
                    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(&gp_keytab_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
}

void gp_keytab_rdlock(void)
{
    pthread_once(&gp_keytab_lock_once, gp_keytab_lock_init);
    pthread_rwlock_rdlock(&gp_keytab_lock);
}

void gp_keytab_unlock(void)
{
    pthread_rwlock_unlock(&gp_keytab_lock);
}

static bool gp_keytab_trywrlock(void)
{
    pthread_once(&gp_keytab_lock_once, gp_keytab_lock_init);
    return pthread_rwlock_trywrlock(&gp_keytab_lock) == 0;
}

static void loader_run(struct gp_keytab_loader *l);

/* ---- keytab manipulation (main thread only) ---- */

static int open_keys(int fd, krb5_keytab *kt)
{
    char name[sizeof("FILE:/proc/self/fd/") + 12];

    snprintf(name, sizeof(name), "FILE:/proc/self/fd/%d", fd);
    return krb5_kt_resolve(gp_kt_ctx, name, kt);
}

static bool same_entry(krb5_keytab_entry *a, krb5_keytab_entry *b)
{
    return a->vno == b->vno &&
           a->key.enctype == b->key.enctype &&
           a->key.length == b->key.length &&
           memcmp(a->key.contents, b->key.contents, a->key.length) == 0 &&
           krb5_principal_compare(gp_kt_ctx, a->principal, b->principal);
}

static bool kt_has_entry(krb5_keytab kt, krb5_keytab_entry *entry)
{
    krb5_kt_cursor cursor;
    krb5_keytab_entry e;
    bool found = false;

    if (krb5_kt_start_seq_get(gp_kt_ctx, kt, &cursor) != 0) {
        return false;
    }
    while (!found && krb5_kt_next_entry(gp_kt_ctx, kt, &e, &cursor) == 0) {
        found = same_entry(&e, entry);
        krb5_free_keytab_entry_contents(gp_kt_ctx, &e);
    }
    krb5_kt_end_seq_get(gp_kt_ctx, kt, &cursor);
    return found;
}

/* Copy the entries of the keytab in fd to dst; with only_missing, skip the
 * ones dst already has.  Counts the entries of the source in *count. */
static krb5_error_code copy_keys(int fd, krb5_keytab dst, bool only_missing,
                                 int *count)
{
    krb5_keytab src = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry e;
    krb5_error_code ret;

    *count = 0;

    ret = open_keys(fd, &src);
    if (ret) {
        return ret;
    }
    ret = krb5_kt_start_seq_get(gp_kt_ctx, src, &cursor);
    if (ret) {
        goto done;
    }
    while ((ret = krb5_kt_next_entry(gp_kt_ctx, src, &e, &cursor)) == 0) {
        (*count)++;
        if (dst && !(only_missing && kt_has_entry(dst, &e))) {
            ret = krb5_kt_add_entry(gp_kt_ctx, dst, &e);
        }
        krb5_free_keytab_entry_contents(gp_kt_ctx, &e);
        if (ret) {
            break;
        }
    }
    krb5_kt_end_seq_get(gp_kt_ctx, src, &cursor);
    if (ret == KRB5_KT_END) {
        ret = 0;
    }

done:
    krb5_kt_close(gp_kt_ctx, src);
    return ret;
}

/* Remove every entry.  Callers hold gp_keytab_lock for writing. */
static krb5_error_code clear_keys(krb5_keytab kt)
{
    krb5_kt_cursor cursor;
    krb5_keytab_entry e;
    krb5_error_code ret;

    do {
        ret = krb5_kt_start_seq_get(gp_kt_ctx, kt, &cursor);
        if (ret) {
            return ret;
        }
        ret = krb5_kt_next_entry(gp_kt_ctx, kt, &e, &cursor);
        krb5_kt_end_seq_get(gp_kt_ctx, kt, &cursor);
        if (ret == 0) {
            ret = krb5_kt_remove_entry(gp_kt_ctx, kt, &e);
            krb5_free_keytab_entry_contents(gp_kt_ctx, &e);
        }
    } while (ret == 0);

    return ret == KRB5_KT_END ? 0 : ret;
}

static void loader_free(struct gp_keytab_loader *l)
{
    if (l->kt) {
        krb5_kt_close(gp_kt_ctx, l->kt);
    }
    for (int i = 0; l->argv && l->argv[i]; i++) {
        free(l->argv[i]);
    }
    free(l->argv);
    free(l->ktname);
    free(l);
}

static void loader_unlink(struct gp_keytab_loader *l)
{
    struct gp_keytab_loader **p;

    for (p = &l->gpctx->kt_loaders; *p; p = &(*p)->next) {
        if (*p == l) {
            *p = l->next;
            break;
        }
    }
}

/* Make the MEMORY keytab hold exactly the pending keys (none for a loader
 * no longer in use).  Returns false if workers are busy and only the new
 * keys could be added. */
static bool install_keys(struct gp_keytab_loader *l, bool locked)
{
    krb5_keytab kt = l->kt;
    krb5_error_code ret;
    int count = 0;

    if (!locked) {
        /* workers are busy: make the new keys usable now */
        if (l->keys_fd != -1) {
            ret = copy_keys(l->keys_fd, kt, true, &count);
            if (ret) {
                GPERROR("Failed to add keys to %s: %d\n", l->ktname, ret);
            }
        }
        return false;
    }

    ret = clear_keys(kt);
    if (ret == 0 && l->keys_fd != -1) {
        ret = copy_keys(l->keys_fd, kt, false, &count);
    }
    if (ret) {
        GPERROR("Failed to replace the keys of %s: %d\n", l->ktname, ret);
    } else {
        GPDEBUG("Keytab %s now holds %d entries.\n", l->ktname, count);
    }

    if (l->keys_fd != -1) {
        close(l->keys_fd);
        l->keys_fd = -1;
    }
    return true;
}

static void swap_keys(struct gp_keytab_loader *l);

static void swap_retry(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    swap_keys(verto_get_private(ev));
}

static void swap_keys(struct gp_keytab_loader *l)
{
    bool locked = gp_keytab_trywrlock();
    bool done;

    done = install_keys(l, locked);
    if (locked) {
        gp_keytab_unlock();
    }

    if (done) {
        if (l->swap_ev) {
            verto_del(l->swap_ev);
            l->swap_ev = NULL;
        }
        if (!l->argv) {
            /* the keytab is no longer configured and is now empty */
            loader_unlink(l);
            loader_free(l);
        }
        return;
    }

    if (!l->swap_ev) {
        l->swap_ev = verto_add_timeout(l->gpctx->vctx, VERTO_EV_FLAG_PERSIST,
                                       swap_retry, GP_KT_SWAP_RETRY);
        if (!l->swap_ev) {
            GPERROR("Failed to schedule key replacement for %s\n",
                    l->ktname);
            return;
        }
        verto_set_private(l->swap_ev, l, NULL);
    }
}

/* ---- running the loader ---- */

static void loader_reset_child(struct gp_keytab_loader *l)
{
    if (l->child_ev) {
        verto_del(l->child_ev);     /* closes the pidfd */
        l->child_ev = NULL;
    }
    if (l->timeout_ev) {
        verto_del(l->timeout_ev);
        l->timeout_ev = NULL;
    }
    if (l->memfd != -1) {
        close(l->memfd);
        l->memfd = -1;
    }
    l->pid = 0;
}

static void loader_kill(struct gp_keytab_loader *l)
{
    int status;

    if (l->pid > 0) {
        kill(l->pid, SIGKILL);
        while (waitpid(l->pid, &status, 0) == -1 && errno == EINTR);
    }
    loader_reset_child(l);
}

static void loader_retry(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    struct gp_keytab_loader *l = verto_get_private(ev);

    l->retry_ev = NULL;     /* not persistent: freed by verto */
    loader_run(l);
}

static void loader_failed(struct gp_keytab_loader *l)
{
    if (l->retry_ev || !l->argv) {
        return;
    }

    GPDEBUG("Retrying keytab loader for %s in %d seconds.\n",
            l->ktname, l->backoff / 1000);
    l->retry_ev = verto_add_timeout(l->gpctx->vctx, VERTO_EV_FLAG_NONE,
                                    loader_retry, l->backoff);
    if (!l->retry_ev) {
        GPERROR("Failed to schedule keytab loader retry for %s\n",
                l->ktname);
        return;
    }
    verto_set_private(l->retry_ev, l, NULL);

    l->backoff *= 2;
    if (l->backoff > GP_KT_RETRY_MAX) {
        l->backoff = GP_KT_RETRY_MAX;
    }
}

static void loader_timeout(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    struct gp_keytab_loader *l = verto_get_private(ev);

    l->timeout_ev = NULL;   /* not persistent: freed by verto */
    GPERROR("Keytab loader for %s timed out, killing it\n", l->ktname);
    loader_kill(l);
    loader_failed(l);
}

/* Check the loader's output: a non-empty keytab that parses fully. */
static int check_output(struct gp_keytab_loader *l, int *count)
{
    struct stat st;
    int ret;

    if (fstat(l->memfd, &st) == -1) {
        return errno;
    }
    if (st.st_size == 0 || st.st_size > GP_KT_MAX_SIZE) {
        GPERROR("Keytab loader for %s produced %lld bytes\n",
                l->ktname, (long long)st.st_size);
        return EINVAL;
    }

    ret = copy_keys(l->memfd, NULL, false, count);
    if (ret == 0 && *count == 0) {
        ret = KRB5_KT_NOTFOUND;
    }
    if (ret) {
        GPERROR("Keytab loader for %s produced an unusable keytab: %d\n",
                l->ktname, ret);
    }
    return ret;
}

static void loader_exited(verto_ctx *vctx UNUSED, verto_ev *ev)
{
    struct gp_keytab_loader *l = verto_get_private(ev);
    int status = 0;
    int count = 0;
    int ret;

    /* not persistent: freed by verto, which closes the pidfd */
    l->child_ev = NULL;

    do {
        ret = waitpid(l->pid, &status, 0);
    } while (ret == -1 && errno == EINTR);
    l->pid = 0;

    if (ret == -1) {
        GPERROR("Failed to reap keytab loader for %s: %d\n",
                l->ktname, errno);
        ret = 1;
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        ret = check_output(l, &count);
    } else {
        if (WIFEXITED(status)) {
            GPERROR("Keytab loader for %s exited with status %d\n",
                    l->ktname, WEXITSTATUS(status));
        } else {
            GPERROR("Keytab loader for %s killed by signal %d\n",
                    l->ktname, WTERMSIG(status));
        }
        ret = 1;
    }

    if (ret == 0) {
        GPAUDIT("Keytab loader for %s loaded %d entries\n",
                l->ktname, count);
        GPDEBUG("Keytab loader for %s loaded %d entries.\n",
                l->ktname, count);
        if (l->keys_fd != -1) {
            close(l->keys_fd);
        }
        l->keys_fd = l->memfd;
        l->memfd = -1;
        l->backoff = GP_KT_RETRY_MIN;
    }

    loader_reset_child(l);

    if (ret == 0) {
        swap_keys(l);
    }

    if (l->rerun) {
        l->rerun = false;
        loader_run(l);
    } else if (ret != 0) {
        loader_failed(l);
    }
}

/* In the child, between fork() and exec(): async-signal-safe calls only. */
static void loader_exec(char **argv, int memfd)
{
    struct sigaction sa = { .sa_handler = SIG_DFL };
    sigset_t set;

    sigemptyset(&set);
    sigprocmask(SIG_SETMASK, &set, NULL);
    /* ignored signals stay ignored across exec */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    if (memfd == GP_KT_LOADER_FD) {
        if (fcntl(memfd, F_SETFD, 0) == -1) {
            _exit(127);
        }
    } else if (dup2(memfd, GP_KT_LOADER_FD) == -1) {
        _exit(127);
    }

#ifdef HAVE_CLOSE_RANGE
    close_range(GP_KT_LOADER_FD + 1, ~0U, 0);
#else
    for (int fd = GP_KT_LOADER_FD + 1; fd < 65536; fd++) {
        close(fd);
    }
#endif

    execv(argv[0], argv);
    _exit(127);
}

static void loader_run(struct gp_keytab_loader *l)
{
    int pidfd = -1;
    int ret;

    if (l->pid) {
        l->rerun = true;
        return;
    }
    if (l->retry_ev) {
        verto_del(l->retry_ev);
        l->retry_ev = NULL;
    }

    GPDEBUG("Running keytab loader %s for %s.\n", l->argv[0], l->ktname);

    l->memfd = memfd_create("gssproxy-keytab", MFD_CLOEXEC);
    if (l->memfd == -1) {
        ret = errno;
        GPERROR("memfd_create failed for %s: %d (%s)\n",
                l->ktname, ret, gp_strerror(ret));
        goto fail;
    }

    l->pid = fork();
    if (l->pid == -1) {
        ret = errno;
        l->pid = 0;
        GPERROR("fork failed for the keytab loader of %s: %d (%s)\n",
                l->ktname, ret, gp_strerror(ret));
        goto fail;
    }
    if (l->pid == 0) {
        loader_exec(l->argv, l->memfd);
    }

    /* the child is not reaped until we wait for it, so its pid is stable */
    pidfd = pidfd_open(l->pid, 0);
    if (pidfd == -1) {
        ret = errno;
        GPERROR("pidfd_open failed for the keytab loader of %s: %d (%s)\n",
                l->ktname, ret, gp_strerror(ret));
        goto fail;
    }

    l->child_ev = verto_add_io(l->gpctx->vctx,
                               VERTO_EV_FLAG_IO_READ |
                               VERTO_EV_FLAG_IO_CLOSE_FD,
                               loader_exited, pidfd);
    if (!l->child_ev) {
        close(pidfd);
        GPERROR("Failed to watch the keytab loader of %s\n", l->ktname);
        goto fail;
    }
    verto_set_private(l->child_ev, l, NULL);

    l->timeout_ev = verto_add_timeout(l->gpctx->vctx, VERTO_EV_FLAG_NONE,
                                      loader_timeout, GP_KT_LOADER_TIMEOUT);
    if (l->timeout_ev) {
        verto_set_private(l->timeout_ev, l, NULL);
    }
    return;

fail:
    loader_kill(l);
    loader_failed(l);
}

/* ---- configuration ---- */

static struct gp_keytab_loader *find_loader(struct gssproxy_ctx *gpctx,
                                            const char *ktname)
{
    struct gp_keytab_loader *l;

    for (l = gpctx->kt_loaders; l; l = l->next) {
        if (strcmp(l->ktname, ktname) == 0) {
            return l;
        }
    }
    return NULL;
}

static char **copy_argv(char **argv)
{
    char **copy;
    int n;

    for (n = 0; argv[n]; n++);
    copy = calloc(n + 1, sizeof(char *));
    if (!copy) {
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        copy[i] = strdup(argv[i]);
        if (!copy[i]) {
            for (int j = 0; j < i; j++) {
                free(copy[j]);
            }
            free(copy);
            return NULL;
        }
    }
    return copy;
}

static void loader_set_argv(struct gp_keytab_loader *l, char **argv)
{
    for (int i = 0; l->argv && l->argv[i]; i++) {
        free(l->argv[i]);
    }
    free(l->argv);
    l->argv = argv;
}

/* Start, re-run or retire the loaders after (re)reading the configuration. */
void gp_keytab_loaders_update(struct gssproxy_ctx *gpctx)
{
    struct gp_keytab_loader *l, *next;
    struct gp_service *svc;
    const char *ktname;
    char **argv;
    krb5_error_code ret;

    for (l = gpctx->kt_loaders; l; l = l->next) {
        l->in_use = false;
    }

    for (int i = 0; i < gpctx->config->num_svcs; i++) {
        svc = gpctx->config->svcs[i];
        if (!svc->keytab_loader) {
            continue;
        }
        ktname = gp_service_get_keytab(svc);

        if (!gp_kt_ctx) {
            ret = krb5_init_context(&gp_kt_ctx);
            if (ret) {
                GPERROR("Failed to initialize krb5 context for keytab "
                        "loaders: %d\n", ret);
                return;
            }
        }

        /* keep the keys out of core dumps */
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

        l = find_loader(gpctx, ktname);
        if (l && l->in_use) {
            /* already handled for another service */
            continue;
        }
        if (!l) {
            l = calloc(1, sizeof(struct gp_keytab_loader));
            if (!l || !(l->ktname = strdup(ktname))) {
                free(l);
                GPERROR("Out of memory setting up keytab loader for %s\n",
                        ktname);
                continue;
            }
            ret = krb5_kt_resolve(gp_kt_ctx, ktname, &l->kt);
            if (ret) {
                GPERROR("Failed to resolve keytab %s: %d\n", ktname, ret);
                loader_free(l);
                continue;
            }
            l->gpctx = gpctx;
            l->memfd = -1;
            l->keys_fd = -1;
            l->backoff = GP_KT_RETRY_MIN;
            l->next = gpctx->kt_loaders;
            gpctx->kt_loaders = l;
        }

        argv = copy_argv(svc->keytab_loader);
        if (!argv) {
            GPERROR("Out of memory setting up keytab loader for %s\n",
                    ktname);
            continue;
        }
        if (!l->argv && l->swap_ev) {
            /* revived before its keys were dropped: keep them */
            verto_del(l->swap_ev);
            l->swap_ev = NULL;
        }
        loader_set_argv(l, argv);
        l->in_use = true;
        l->backoff = GP_KT_RETRY_MIN;
        loader_run(l);
    }

    for (l = gpctx->kt_loaders; l; l = next) {
        next = l->next;
        if (l->in_use || !l->argv) {
            continue;
        }
        /* no service uses this keytab any more: drop its keys */
        GPDEBUG("Keytab %s is no longer configured, dropping it.\n",
                l->ktname);
        loader_kill(l);
        l->rerun = false;
        if (l->retry_ev) {
            verto_del(l->retry_ev);
            l->retry_ev = NULL;
        }
        loader_set_argv(l, NULL);
        if (l->keys_fd != -1) {
            close(l->keys_fd);
            l->keys_fd = -1;
        }
        swap_keys(l);
    }
}

void gp_keytab_loaders_fini(struct gssproxy_ctx *gpctx)
{
    struct gp_keytab_loader *l;

    while ((l = gpctx->kt_loaders)) {
        gpctx->kt_loaders = l->next;
        loader_kill(l);
        if (l->retry_ev) {
            verto_del(l->retry_ev);
        }
        if (l->swap_ev) {
            verto_del(l->swap_ev);
        }
        if (l->keys_fd != -1) {
            close(l->keys_fd);
        }
        loader_free(l);
    }

    if (gp_kt_ctx) {
        krb5_free_context(gp_kt_ctx);
        gp_kt_ctx = NULL;
    }
}

#else /* !(HAVE_MEMFD_CREATE && HAVE_PIDFD_OPEN) */

#include "gp_proxy.h"

/* configurations with keytab_loader are rejected when parsed */
void gp_keytab_loaders_update(struct gssproxy_ctx *gpctx UNUSED) {}
void gp_keytab_loaders_fini(struct gssproxy_ctx *gpctx UNUSED) {}
void gp_keytab_rdlock(void) {}
void gp_keytab_unlock(void) {}

#endif
