
t_accept_SOURCES = \
    t_utils.c \
    t_accept.c

t_accept_LDADD = \
    $(GSSAPI_LIBS)

t_init_SOURCES = \
    t_utils.c \
    t_init.c

t_init_LDADD = \
    $(GSSAPI_LIBS)

check_PROGRAMS = \
    t_accept \
    t_init

noinst_PROGRAMS = $(check_PROGRAMS)

noinst_HEADERS = \
    t_utils.h

all: $(check_PROGRAMS)
