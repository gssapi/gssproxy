/* Copyright (C) 2012 the GSS-PROXY contributors, see COPYING for license */

#include "gss_plugin.h"
#include <signal.h>
#include <endian.h>
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
        envval = gp_getenv("GSSPROXY_BEHAVIOR");
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
                /* unknown setting, default to what has been configured
                 * (by default local first) */
                behavior = GPP_DEFAULT_BEHAVIOR;
            }
        } else {
            /* default to what has been configured (by default local only) */
            behavior = GPP_DEFAULT_BEHAVIOR;
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
    envval = gp_getenv("GSS_USE_PROXY");
    if (!envval) {
        return NULL;
    }

    if (!gp_boolean_is_true(envval)) {
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
    gss_OID_desc regular_oid;
    gss_OID_desc special_oid;
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
    item->regular_oid.length = n->length;
    item->regular_oid.elements = malloc(n->length);
    item->special_oid.length = base->length + n->length;
    item->special_oid.elements = malloc(item->special_oid.length);
    if (!item->regular_oid.elements ||
        !item->special_oid.elements) {
        free(item->regular_oid.elements);
        free(item->special_oid.elements);
        free(item);
        return GSS_C_NO_OID;
    }

    memcpy(item->regular_oid.elements, n->elements, n->length);
    memcpy(item->special_oid.elements, base->elements, base->length);
    memcpy(item->special_oid.elements + base->length, n->elements, n->length);

    gpp_add_special_oids(item);

    return (const gss_OID)&item->special_oid;
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
            return (const gss_OID)&item->special_oid;
        }
        return GSS_C_NO_OID;
    }

    while (item) {
        if (gpp_special_equal(&item->special_oid, mech_type)) {
            return (const gss_OID)&item->special_oid;
        }
        item = gpp_next_special_oids(item);
    }

    /* none matched, add new special oid to the set */
    return gpp_new_special_mech(mech_type);
}

const gss_OID gpp_unspecial_mech(const gss_OID mech_type)
{
    struct gpp_special_oid_list *item = NULL;

    if (!gpp_is_special_oid(mech_type)) {
        return mech_type;
    }

    item = gpp_get_special_oids();
    while (item) {
        if (gss_oid_equal(&item->special_oid, mech_type)) {
            return (const gss_OID)&item->regular_oid;
        }
        item = gpp_next_special_oids(item);
    }

    /* none matched */
    return mech_type;
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
            if (gpp_special_equal(&item->special_oid, &mechs->elements[i])) {
                maj = gss_add_oid_set_member(&min, &item->special_oid,
                                             &amechs);
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

OM_uint32 gssi_internal_release_oid(OM_uint32 *minor_status, gss_OID *oid)
{
    struct gpp_special_oid_list *item = NULL;

    *minor_status = 0;

    if (&gssproxy_mech_interposer == *oid) {
        *oid = GSS_C_NO_OID;
        return GSS_S_COMPLETE;
    }

    item = gpp_get_special_oids();

    while (item) {
        if ((&item->regular_oid == *oid) ||
            (&item->special_oid == *oid)) {
            *oid = GSS_C_NO_OID;
            return GSS_S_COMPLETE;
        }
        item = gpp_next_special_oids(item);
    }

    /* none matched, it's not ours */
    return GSS_S_CONTINUE_NEEDED;
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

uint32_t gpp_wrap_sec_ctx_token(uint32_t *minor, gss_OID mech_type,
                                gss_buffer_t token, gss_buffer_t wrap_token)
{
    gss_OID spmech;
    uint32_t len;

    spmech = gpp_special_mech(mech_type);
    if (spmech == GSS_C_NO_OID) {
        return GSS_S_FAILURE;
    }

    wrap_token->length = sizeof(uint32_t) + spmech->length + token->length;
    wrap_token->value = malloc(wrap_token->length);
    if (!wrap_token->value) {
        wrap_token->length = 0;
        return GSS_S_FAILURE;
    }

    len = htobe32(spmech->length);
    memcpy(wrap_token->value, &len, sizeof(uint32_t));
    memcpy(wrap_token->value + sizeof(uint32_t),
           spmech->elements, spmech->length);
    memcpy(wrap_token->value + sizeof(uint32_t) + spmech->length,
           token->value, token->length);

    return GSS_S_COMPLETE;
}

uint32_t gpp_remote_to_local_ctx(uint32_t *minor, gssx_ctx **remote_ctx,
                                 gss_ctx_id_t *local_ctx)
{
    gss_buffer_desc wrap_token = {0};
    gss_buffer_desc token;
    gss_OID_desc mech;
    uint32_t hlen, len;
    uint32_t maj, min;

    gp_conv_gssx_to_buffer(&(*remote_ctx)->exported_context_token, &token);

    /* To get a local context we need to call import_sec_context with a token
     * wrapping that uses the special mech oid. Otherwise the mechglue will
     * give us back an interposed context. */

    if (token.length <= sizeof(uint32_t)) {
        return GSS_S_FAILURE;
    }

    memcpy(&len, token.value, sizeof(uint32_t));
    mech.length = be32toh(len);

    hlen = sizeof(uint32_t) + mech.length;
    if (token.length <= hlen) {
        return GSS_S_FAILURE;
    }
    mech.elements = malloc(mech.length);
    if (!mech.elements) {
        return GSS_S_FAILURE;
    }
    memcpy(mech.elements, token.value + sizeof(uint32_t), mech.length);

    token.length -= hlen;
    token.value += hlen;

    maj = gpp_wrap_sec_ctx_token(&min, &mech, &token, &wrap_token);
    if (maj != GSS_S_COMPLETE) {
        free(mech.elements);
        return maj;
    }

    maj = gss_import_sec_context(minor, &wrap_token, local_ctx);

    free(mech.elements);
    (void)gss_release_buffer(&min, &wrap_token);
    xdr_free((xdrproc_t)xdr_gssx_ctx, (char *)(*remote_ctx));
    *remote_ctx = NULL;
    return maj;
}

uint32_t gpp_name_to_local(uint32_t *minor, gssx_name *name,
                           gss_OID mech_type, gss_name_t *mech_name)
{
    uint32_t maj, min;
    gss_buffer_desc display_name_buffer = GSS_C_EMPTY_BUFFER;
    gss_OID display_name_type = GSS_C_NO_OID;
    gss_name_t tmpname = NULL;

    maj = gpm_display_name(minor, name,
                           &display_name_buffer,
                           &display_name_type);
    if (maj) {
        return maj;
    }

    maj = gss_import_name(minor,
                          &display_name_buffer,
                          display_name_type,
                          &tmpname);

    (void)gss_release_buffer(&min, &display_name_buffer);
    (void)gss_release_oid(&min, &display_name_type);

    if (maj) {
        return maj;
    }

    if (mech_type != GSS_C_NO_OID) {
        /* name for specific mech requested */
        maj = gss_canonicalize_name(minor,
                                    tmpname,
                                    gpp_special_mech(mech_type),
                                    NULL);
    }

    *mech_name = tmpname;
    return maj;
}

uint32_t gpp_local_to_name(uint32_t *minor,
                           gss_name_t local_name, gssx_name **name)
{
    uint32_t maj, min;
    gss_buffer_desc display_name_buffer = GSS_C_EMPTY_BUFFER;
    gss_OID display_name_type = GSS_C_NO_OID;

    maj = gss_display_name(minor, local_name,
                           &display_name_buffer,
                           &display_name_type);
    if (maj) {
        return maj;
    }

    maj = gpm_import_name(minor,
                          &display_name_buffer,
                          display_name_type,
                          name);

    (void)gss_release_buffer(&min, &display_name_buffer);
    (void)gss_release_oid(&min, &display_name_type);
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

bool gpp_is_krb5_oid(const gss_OID mech)
{
    if (gss_oid_equal(&gpoid_krb5, mech)) {
        return true;
    } else if (gss_oid_equal(&gpoid_krb5_old, mech)) {
        return true;
    } else if (gss_oid_equal(&gpoid_krb5_wrong, mech)) {
        return true;
    } else if (gss_oid_equal(&gpoid_iakerb, mech)) {
        return true;
    }
    return false;
}
