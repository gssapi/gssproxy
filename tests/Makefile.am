t_acquire_SOURCES = \
    t_utils.c \
    t_acquire.c

t_acquire_LDADD = \
    $(GSSAPI_LIBS)

t_accept_SOURCES = \
    t_utils.c \
    t_accept.c

t_accept_LDADD = \
    $(GSSAPI_LIBS)

t_cred_store_SOURCES = \
    t_utils.c \
    t_cred_store.c

t_cred_store_LDADD = \
    $(GSSAPI_LIBS)

t_impersonate_SOURCES = \
    t_utils.c \
    t_impersonate.c

t_impersonate_LDADD = \
    $(GSSAPI_LIBS)

t_init_SOURCES = \
    t_utils.c \
    t_init.c

t_init_LDADD = \
    $(GSSAPI_LIBS)

t_setcredopt_SOURCES = \
    t_utils.c \
    t_setcredopt.c

t_setcredopt_LDADD = \
    $(GSSAPI_LIBS)

check_PROGRAMS = \
    t_acquire \
    t_cred_store \
    t_impersonate \
    t_accept \
    t_init \
    t_setcredopt \
    $(NULL)

noinst_PROGRAMS = $(check_PROGRAMS)

noinst_HEADERS = \
    t_utils.h

EXTRA_DIST = \
    runtests.py \
    t_acquire.py \
    t_basic.py \
    t_cred_store.py \
    testlib.py \
    t_impersonate.py \
    t_interpose.py \
    t_multi_key.py \
    t_reloading.py \
    $(NULL)

all: $(check_PROGRAMS)
