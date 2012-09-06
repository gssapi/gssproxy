/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Simo Sorce <simo.sorce@redhat.com>

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

#include "gss_plugin.h"
#include <signal.h>
#include <gssapi/gssapi_krb5.h>

#define KRB5_OID_LEN 9
#define KRB5_OID "\052\206\110\206\367\022\001\002\002"

#define KRB5_OLD_OID_LEN 5
#define KRB5_OLD_OID "\053\005\001\005\002"

/* Incorrect krb5 mech OID emitted by MS. */
#define KRB5_WRONG_OID_LEN 9
#define KRB5_WRONG_OID "\052\206\110\202\367\022\001\002\002"

#define IAKERB_OID_LEN 6
#define IAKERB_OID "\053\006\001\005\002\005"

const gss_OID_desc gpoid_krb5 = {
    .length = KRB5_OID_LEN,
    .elements = KRB5_OID
};
const gss_OID_desc gpoid_krb5_old = {
    .length = KRB5_OLD_OID_LEN,
    .elements = KRB5_OLD_OID
};
const gss_OID_desc gpoid_krb5_wrong = {
    .length = KRB5_WRONG_OID_LEN,
    .elements = KRB5_WRONG_OID
};
const gss_OID_desc gpoid_iakerb = {
    .length = IAKERB_OID_LEN,
    .elements = IAKERB_OID
};

enum gpp_behavior gpp_get_behavior(void)
{
    static enum gpp_behavior behavior = GPP_UNINITIALIZED;
    char *envval;

    if (behavior == GPP_UNINITIALIZED) {
        envval = getenv("GSSPROXY_BEHAVIOR");
        if (envval) {
            if (strcmp(envval, "LOCAL_ONLY") == 0) {
                behavior = GPP_LOCAL_ONLY;
            } else if (strcmp(envval, "LOCAL_FIRST") == 0) {
                behavior = GPP_LOCAL_FIRST;
            } else if (strcmp(envval, "REMOTE_FIRST") == 0) {
                behavior = GPP_REMOTE_FIRST;
            } else if (strcmp(envval, "REMOTE_ONLY") == 0) {
                behavior = GPP_REMOTE_ONLY;
            } else {
                /* unknwon setting, default to local first */
                behavior = GPP_LOCAL_FIRST;
            }
        } else {
            /* default to local only for now */
            behavior = GPP_LOCAL_FIRST;
        }
    }

    return behavior;
}

/* 2.16.840.1.113730.3.8.15.1 */
const gss_OID_desc gssproxy_mech_interposer = {
    .length = 11,
    .elements = "\140\206\110\001\206\370\102\003\010\017\001"
};

gss_OID_set gss_mech_interposer(gss_OID mech_type)
{
    gss_OID_set interposed_mechs;
    OM_uint32 maj, min;
    char *envval;

    /* avoid looping in the gssproxy daemon by avoiding to interpose
     * any mechanism */
    envval = getenv("_GSSPROXY_LOOPS");
    if (envval && strcmp(envval, "NO") == 0) {
        return NULL;
    }

    interposed_mechs = NULL;
    maj = 0;
    if (gss_oid_equal(&gssproxy_mech_interposer, mech_type)) {
        maj = gss_create_empty_oid_set(&min, &interposed_mechs);
        if (maj != 0) {
            return NULL;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_old),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_krb5_wrong),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
        maj = gss_add_oid_set_member(&min, no_const(&gpoid_iakerb),
                                     &interposed_mechs);
        if (maj != 0) {
            goto done;
        }
    }

    /* while there also initiaize special_mechs */
    (void)gpp_special_available_mechs(interposed_mechs);

done:
    if (maj != 0) {
        (void)gss_release_oid_set(&min, &interposed_mechs);
        interposed_mechs = NULL;
    }

    return interposed_mechs;
}

bool gpp_is_special_oid(const gss_OID mech_type)
{
    if (mech_type != GSS_C_NO_OID &&
        mech_type->length >= gssproxy_mech_interposer.length &&
        memcmp(gssproxy_mech_interposer.elements,
               mech_type->elements,
               gssproxy_mech_interposer.length) == 0) {
        return true;
    }
    return false;
}

static bool gpp_special_equal(const gss_OID s, const gss_OID n)
{
    int base_len = gssproxy_mech_interposer.length;

    if (s->length - base_len == n->length &&
        memcmp(s->elements + base_len, n->elements, n->length) == 0) {
        return true;
    }
    return false;
}

struct gpp_special_oid_list {
    gss_OID_desc oid;
    struct gpp_special_oid_list *next;
    sig_atomic_t next_is_set;
};

/* This is an ADD-ONLY list, and the pointer to next is updated
 * atomically so that we can avoid using mutexes for mere access
 * to the list. */
static struct gpp_special_oid_list *gpp_s_mechs;
static sig_atomic_t gpp_s_mechs_is_set;

static inline struct gpp_special_oid_list *gpp_get_special_oids(void)
{
    int is_set;

    is_set = gpp_s_mechs_is_set;
    __sync_synchronize();
    if (is_set != 0) {
        return gpp_s_mechs;
    }
    return NULL;
}

static inline struct gpp_special_oid_list *gpp_next_special_oids(
                                            struct gpp_special_oid_list *item)
{
    int is_set;

    is_set = item->next_is_set;
    __sync_synchronize();
    if (is_set != 0) {
        return item->next;
    }
    return NULL;
}

static inline struct gpp_special_oid_list *gpp_last_special_oids(
                                            struct gpp_special_oid_list *list)
{
    struct gpp_special_oid_list *item;

    item = list;
    while (item && item->next_is_set) {
        item = item->next;
    }
    return item;
}

static inline void gpp_add_special_oids(struct gpp_special_oid_list *item)
{
    struct gpp_special_oid_list *list, *last;

    list = gpp_get_special_oids();
    if (list == NULL) {
        gpp_s_mechs = item;
        __sync_synchronize();
        gpp_s_mechs_is_set = 1;
    } else {
        last = gpp_last_special_oids(list);
        last->next = item;
        __sync_synchronize();
        last->next_is_set = 1;
    }
}

static const gss_OID gpp_new_special_mech(const gss_OID n)
{
    gss_const_OID base = &gssproxy_mech_interposer;
    struct gpp_special_oid_list *item;

    item = calloc(1, sizeof(struct gpp_special_oid_list));
    if (!item) {
        return GSS_C_NO_OID;
    }
    item->oid.length = base->length + n->length;
    item->oid.elements = malloc(item->oid.length);
    if (!item->oid.elements) {
        free(item);
        return GSS_C_NO_OID;
    }

    memcpy(item->oid.elements, base->elements, base->length);
    memcpy(item->oid.elements + base->length, n->elements, n->length);

    gpp_add_special_oids(item);

    return (const gss_OID)&item->oid;
}

const gss_OID gpp_special_mech(const gss_OID mech_type)
{
    struct gpp_special_oid_list *item = NULL;

    if (gpp_is_special_oid(mech_type)) {
        return mech_type;
    }

    item = gpp_get_special_oids();

    if (mech_type == GSS_C_NO_OID) {
        /* return the first special one if none specified */
        if (item) {
            return (const gss_OID)&item->oid;
        }
        return GSS_C_NO_OID;
    }

    while (item) {
        if (gpp_special_equal(&item->oid, mech_type)) {
            return (const gss_OID)&item->oid;
        }
        item = gpp_next_special_oids(item);
    }

    /* none matched, add new special oid to the set */
    return gpp_new_special_mech(mech_type);
}

gss_OID_set gpp_special_available_mechs(const gss_OID_set mechs)
{
    gss_OID_set amechs = GSS_C_NO_OID_SET;
    struct gpp_special_oid_list *item;
    gss_OID n;
    uint32_t maj, min;
    int i;

    item = gpp_get_special_oids();

    maj = gss_create_empty_oid_set(&min, &amechs);
    if (maj) {
        return GSS_C_NO_OID_SET;
    }
    for (i = 0; i < mechs->count; i++) {
        while (item) {
            if (gpp_is_special_oid(&mechs->elements[i])) {
                maj = gss_add_oid_set_member(&min,
                                             &mechs->elements[i], &amechs);
                if (maj != GSS_S_COMPLETE) {
                    goto done;
                }
                break;
            }
            if (gpp_special_equal(&item->oid, &mechs->elements[i])) {
                maj = gss_add_oid_set_member(&min, &item->oid, &amechs);
                if (maj != GSS_S_COMPLETE) {
                    goto done;
                }
                break;
            }
            item = gpp_next_special_oids(item);
        }
        if (item == NULL) {
            /* not found, add to static list */
            n = gpp_new_special_mech(&mechs->elements[i]);
            if (n == GSS_C_NO_OID) {
                maj = GSS_S_FAILURE;
            } else {
                maj = gss_add_oid_set_member(&min, n, &amechs);
            }
            if (maj != GSS_S_COMPLETE) {
                goto done;
            }
        }
    }

done:
    if (maj != GSS_S_COMPLETE || amechs->count == 0) {
        (void)gss_release_oid_set(&min, &amechs);
    }
    return amechs;
}

#define MAP_ERROR_BASE 0x04200000

uint32_t gpp_map_error(uint32_t err)
{
    /* placeholder,
     * we will need an actual map but to speed up testing just make a sum with
     * a special base and hope no conflicts will happen in the mechglue */
    if (err) {
        err += MAP_ERROR_BASE;
    }
    return err;
}

uint32_t gpp_unmap_error(uint32_t err)
{
    /* placeholder,
     * we will need an actual map but to speed up testing just make a sum with
     * a special base and hope no conflicts will happen in the mechglue */
    if (err) {
        err -= MAP_ERROR_BASE;
    }
    return err;
}

uint32_t gpp_remote_to_local_ctx(uint32_t *minor, gssx_ctx **remote_ctx,
                                 gss_ctx_id_t *local_ctx)
{
    gss_buffer_desc buf;
    uint32_t maj;

    gp_conv_gssx_to_buffer(&(*remote_ctx)->exported_context_token, &buf);

    maj = gss_import_sec_context(minor, &buf, local_ctx);

    xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)(*remote_ctx));
    *remote_ctx = NULL;

    return maj;
}

uint32_t gpp_copy_oid(uint32_t *minor, gss_OID in, gss_OID *out)
{
    gss_OID c;

    c = calloc(1, sizeof(gss_OID_desc));
    if (!c) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    c->length = in->length;
    c->elements = malloc(in->length);
    if (!c->elements) {
        free(c);
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }
    memcpy(c->elements, in->elements, in->length);

    *out = c;
    *minor = 0;
    return GSS_S_COMPLETE;
}
