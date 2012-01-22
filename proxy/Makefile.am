SUBDIRS =
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
localedir = @localedir@

pidpath = @pidpath@
pipepath = @pipepath@
initdir = @initdir@
systemdunitdir = @systemdunitdir@
logpath = @logpath@
pubconfpath = @pubconfpath@
pkgconfigdir = $(libdir)/pkgconfig

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

dist_noinst_SCRIPTS =

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
    -DLIBDIR=\"$(libdir)\" \
    -DVARDIR=\"$(localstatedir)\" \
    -DSHLIBEXT=\"$(SHLIBEXT)\" \
    -DSYSCONFDIR=\"$(sysconfdir)\" \
    -DLOCALEDIR=\"$(localedir)\"

EXTRA_DIST = build/config.rpath

GSS_PROXY_LIBS = $(POPT_LIBS) $(KRB5_LIBS) $(VERTO_LIBS) $(INI_LIBS) $(GSSAPI_LIBS)

if BUILD_SELINUX
    GSS_PROXY_LIBS += $(SELINUX_LIBS)
endif

GP_RPCGEN_OBJ = rpcgen/gp_rpc_xdr.c rpcgen/gss_proxy_xdr.c

dist_noinst_HEADERS =

####################
# Program Binaries #
####################

gssproxy_SOURCES = \
    src/gp_config.c \
    src/gp_init.c \
    src/gp_socket.c \
    src/gp_workers.c \
    $(GP_RPCGEN_OBJ) \
    src/gp_rpc_process.c \
    src/gp_conv.c \
    src/gp_export.c \
    src/gp_accept_sec_context.c \
    src/gssproxy.c

gssproxy_LDADD = \
    $(GSS_PROXY_LIBS)

dist_noinst_DATA += \
    examples/gssproxy-example.conf \
    m4

noinst_PROGRAMS =

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
dist_systemdunit_DATA =
if HAVE_SYSTEMD_UNIT
    dist_systemdunit_DATA += \
        systemd/gssproxy.service
endif

installgsspdirs::
	mkdir -p \
    $(DESTDIR)$(includedir) \
    $(DESTDIR)$(libdir) \
    $(DESTDIR)$(sbindir) \
    $(DESTDIR)$(mandir) \
    $(DESTDIR)$(gsspconfdir) \
    $(DESTDIR)$(pidpath) \
    $(DESTDIR)$(pipepath) \
    $(DESTDIR)$(logpath) \
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

CLEANFILES = *.X */*.X */*/*.X

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

