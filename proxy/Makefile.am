SUBDIRS = . tests
#SUBDIRS += po

if HAVE_MANPAGES
SUBDIRS += man
endif

# Some old versions of automake don't define builddir
builddir ?= .

DOXYGEN = @DOXYGEN@

DISTSETUPOPTS =
if HAVE_DEBIAN
DISTSETUPOPTS += --install-layout=deb
endif

gssplibdir = $(libdir)/gssproxy
gsspconfdir = $(sysconfdir)/gssproxy
gssconfdir = $(sysconfdir)/gss
localedir = @localedir@

ccpath = @ccpath@
initdir = @initdir@
systemdunitdir = @systemdunitdir@
examplesdir= @datarootdir@/examples
logpath = @logpath@
pubconfpath = @pubconfpath@
pkgconfigdir = $(libdir)/pkgconfig

gpstatedir = @gpstatedir@
gpclidir = @gpstatedir@/clients

AM_CFLAGS =
if WANT_AUX_INFO
    AM_CFLAGS += -aux-info $@.X
endif
if HAVE_GCC
    AM_CFLAGS += -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith \
                 -Wcast-qual -Wcast-align -Wwrite-strings \
                 -Werror-implicit-function-declaration \
                 -fno-strict-aliasing
endif

dist_pkgconfig_DATA =

ACLOCAL_AMFLAGS = -I m4 -I .

sbin_PROGRAMS = \
    gssproxy

check_PROGRAMS = \
    cli_srv_comm interposetest

gssplib_LTLIBRARIES = \
    proxymech.la

dist_noinst_SCRIPTS = tests/scripts/dlopen.sh

dist_noinst_DATA =

###############################
# Global compilation settings #
###############################

AM_CPPFLAGS = \
    -Wall \
    -Iinclude \
    -I.. \
    -I$(srcdir)/include \
    -I$(srcdir) \
    -Iinclude \
    -I. \
    $(POPT_CFLAGS) \
    $(GSSAPI_CFLAGS) \
    $(INI_CFLAGS) \
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    -DLOCALEDIR=\"$(localedir)\"

GSS_PROXY_LIBS = $(POPT_LIBS) $(KRB5_LIBS) $(VERTO_LIBS) $(INI_LIBS) $(GSSAPI_LIBS) $(GSSRPC_LIBS)

if BUILD_SELINUX
    GSS_PROXY_LIBS += $(SELINUX_LIBS)
endif

GP_RPCGEN_OBJ = rpcgen/gp_rpc_xdr.c rpcgen/gss_proxy_xdr.c rpcgen/gp_xdr.c
GP_RPCCLI_OBJ = \
    src/client/gpm_display_status.c \
    src/client/gpm_accept_sec_context.c \
    src/client/gpm_release_handle.c \
    src/client/gpm_acquire_cred.c \
    src/client/gpm_indicate_mechs.c \
    src/client/gpm_import_and_canon_name.c \
    src/client/gpm_init_sec_context.c \
    src/client/gpm_inquire_context.c \
    src/client/gpm_get_mic.c \
    src/client/gpm_verify_mic.c \
    src/client/gpm_wrap.c \
    src/client/gpm_unwrap.c \
    src/client/gpm_wrap_size_limit.c \
    src/client/gpm_common.c \
    src/gp_util.c

GP_MECHGLUE_OBJ = \
    src/mechglue/gpp_accept_sec_context.c \
    src/mechglue/gpp_acquire_cred.c \
    src/mechglue/gpp_creds.c \
    src/mechglue/gpp_context.c \
    src/mechglue/gpp_init_sec_context.c \
    src/mechglue/gpp_display_status.c \
    src/mechglue/gpp_import_and_canon_name.c \
    src/mechglue/gpp_indicate_mechs.c \
    src/mechglue/gpp_priv_integ.c \
    src/mechglue/gpp_misc.c \
    src/mechglue/gss_plugin.c

dist_noinst_HEADERS = \
    rpcgen/gp_rpc.h \
    rpcgen/gp_xdr.h \
    rpcgen/gss_proxy.h \
    src/gp_rpc_process.h \
    src/gp_proxy.h \
    src/client/gssapi_gpm.h \
    src/gp_common.h \
    src/gp_log.h \
    src/gp_creds.h \
    src/gp_export.h \
    src/gp_conv.h \
    src/gp_config.h \
    src/gp_config_iniparser.h \
    src/gp_config_dinglibs.h \
    src/gp_debug.h \
    src/gp_rpc_creds.h \
    src/gp_selinux.h \
    src/mechglue/gss_plugin.h


####################
# Program Binaries #
####################

gssproxy_SOURCES = \
    src/gp_config.c \
    src/gp_config_iniparser.c \
    src/gp_config_dinglibs.c \
    src/gp_init.c \
    src/gp_socket.c \
    src/gp_workers.c \
    src/gp_creds.c \
    $(GP_RPCGEN_OBJ) \
    src/gp_rpc_process.c \
    src/gp_conv.c \
    src/gp_export.c \
    src/gp_debug.c \
    src/gp_log.c \
    src/gp_util.c \
    src/gp_rpc_accept_sec_context.c \
    src/gp_rpc_release_handle.c \
    src/gp_rpc_acquire_cred.c \
    src/gp_rpc_indicate_mechs.c \
    src/gp_rpc_import_and_canon_name.c \
    src/gp_rpc_init_sec_context.c \
    src/gp_rpc_get_mic.c \
    src/gp_rpc_verify_mic.c \
    src/gp_rpc_wrap.c \
    src/gp_rpc_unwrap.c \
    src/gp_rpc_wrap_size_limit.c \
    src/gssproxy.c

proxymech_la_SOURCES = \
    src/gp_conv.c \
    $(GP_RPCGEN_OBJ) \
    $(GP_RPCCLI_OBJ) \
    $(GP_MECHGLUE_OBJ)
proxymech_la_CFLAGS = \
    $(AM_FLAGS)
proxymech_la_LDFLAGS = \
    -avoid-version \
    -module

cli_srv_comm_SOURCES = \
    src/gp_conv.c \
    src/gp_debug.c \
    src/gp_log.c \
    $(GP_RPCGEN_OBJ) \
    $(GP_RPCCLI_OBJ) \
    tests/cli_srv_comm.c

interposetest_SOURCES = \
    src/gp_log.c \
    src/gp_debug.c \
    tests/interposetest.c

gssproxy_LDADD = \
    $(GSS_PROXY_LIBS)

cli_srv_comm_LDADD = \
    $(GSS_PROXY_LIBS)

interposetest_LDADD = \
    $(GSS_PROXY_LIBS)

dist_noinst_DATA += \
    m4

noinst_PROGRAMS = cli_srv_comm interposetest

################
# TRANSLATIONS #
################
update-po:
if HAVE_MANPAGES
	$(MAKE) -C man update-po
endif
#	$(MAKE) -C po update-po

#######################
# Installation Extras #
#######################

dist_init_SCRIPTS =
systemdunit_DATA =
if HAVE_SYSTEMD_UNIT
    systemdunit_DATA += \
        systemd/gssproxy.service
endif

noinst_DATA = examples/gssproxy.conf examples/mech

edit_cmd = $(SED) \
    -e 's|@sbindir[@]|$(sbindir)|g' \
    -e 's|@localstatedir[@]|$(localstatedir)|g' \
    -e 's|@libdir[@]|$(libdir)|g' \
    -e 's|@gpclidir[@]|$(gpclidir)|g'

replace_script = \
    @rm -f $@ $@.tmp; \
    srcdir=''; \
        test -f ./$@.in || srcdir=$(srcdir)/; \
        $(edit_cmd) $${srcdir}$@.in >$@.tmp; \
    mv $@.tmp $@

EXTRA_DIST = \
    systemd/gssproxy.service.in \
    examples/gssproxy.conf.in \
    examples/mech.in

systemd/gssproxy.service: systemd/gssproxy.service.in Makefile
	@$(MKDIR_P) systemd/
	$(replace_script)

examples/gssproxy.conf: examples/gssproxy.conf.in Makefile
	@$(MKDIR_P) examples/
	$(replace_script)

examples/mech: examples/mech.in Makefile
	@$(MKDIR_P) examples/
	$(replace_script)

installgsspdirs::
	mkdir -p \
    $(DESTDIR)$(includedir) \
    $(DESTDIR)$(libdir) \
    $(DESTDIR)$(sbindir) \
    $(DESTDIR)$(mandir) \
    $(DESTDIR)$(gsspconfdir) \
    $(DESTDIR)$(gssconfdir) \
    $(DESTDIR)$(logpath) \
    $(DESTDIR)$(gpstatedir) \
    $(DESTDIR)$(gpclidir) \
    $(DESTDIR)$(pubconfpath)

if HAVE_DOXYGEN
docs:
	$(DOXYGEN) doxy.config
else
docs:
	@echo "Doxygen not installed, cannot generate documentation"
	@exit 1
endif

install-exec-hook: installgsspdirs
	mkdir -p doc $(DESTDIR)/$(docdir); cp -a doc $(DESTDIR)/$(docdir)/
if HAVE_SYSTEMD_UNIT
	mkdir -p $(DESTDIR)$(systemdunitdir)
else
	mkdir -p $(DESTDIR)$(initdir)
endif

clean-local:
	rm -Rf doc

CLEANFILES = *.X */*.X */*/*.X \
    examples/mech \
    examples/gssproxy.conf

tests: all $(check_PROGRAMS)
	$(srcdir)/tests/runtests.py

# RPM-related tasks

RPMBUILD ?= $(PWD)/rpmbuild

dist_noinst_DATA += \
    m4 \
    contrib/gssproxy.spec.in \
    BUILD.txt \
    COPYING

rpmroot:
	mkdir -p $(RPMBUILD)/BUILD
	mkdir -p $(RPMBUILD)/RPMS
	mkdir -p $(RPMBUILD)/SOURCES
	mkdir -p $(RPMBUILD)/SPECS
	mkdir -p $(RPMBUILD)/SRPMS

rpms: dist-gzip rpmroot
	cp $(builddir)/contrib/gssproxy.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" -ba SPECS/gssproxy.spec

if GIT_CHECKOUT
prerelease-rpms:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) rpms
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

# make srpms will use the old digest algorithm to be compatible
# with RHEL5
srpm: dist-gzip rpmroot
	cp $(builddir)/contrib/gssproxy.spec $(RPMBUILD)/SPECS
	cp $(distdir).tar.gz $(RPMBUILD)/SOURCES
	cd $(RPMBUILD); \
	rpmbuild --define "_topdir $(RPMBUILD)" \
	         --define _source_filedigest_algorithm=1 \
	         -bs SPECS/gssproxy.spec

if GIT_CHECKOUT
prerelease-srpm:
	cp $(srcdir)/version.m4 $(srcdir)/version.m4.orig
	sed -e "s/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.*\])/m4_define(\[PRERELEASE_VERSION_NUMBER\], \[.`date +%Y%m%d.%H%M`.git`git log -1 --pretty=format:%h`\])/" < $(srcdir)/version.m4.orig > $(srcdir)/version.m4
	$(MAKE) srpm
	mv $(srcdir)/version.m4.orig $(srcdir)/version.m4
endif

####################
# Testing          #
####################

test_proxymech:
	TMPDIR=tests/scripts/ $(srcdir)/tests/scripts/dlopen.sh ./.libs/proxymech.so || exit 1
