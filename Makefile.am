
ACLOCAL_AMFLAGS = -I m4

JANSSON_INCLUDES= -I$(top_builddir)/compat/jansson-2.5/src -I$(top_srcdir)/compat/jansson-2.5/src

PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)

EXTRA_DIST	= example.conf m4/gnulib-cache.m4 \
		  gpu/adl_sdk/readme.txt api-example.php miner.php	\
		  API.class API.java api-example.c doc/build-windows.md \
		  API-README

SUBDIRS	= lib compat ccan secp256k1

nxminer_INCLUDES = $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES) -I$(top_srcdir)/secp256k1/include

LIBSECP256K1=secp256k1/.libs/libsecp256k1.a

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

bin_PROGRAMS = nxminer

bin_SCRIPTS	= *.cl

nxminer_LDFLAGS	= $(PTHREAD_FLAGS)
nxminer_LDADD	= $(DLOPEN_FLAGS) @LIBCURL_LIBS@ @JANSSON_LIBS@ @PTHREAD_LIBS@ \
		  @OPENCL_LIBS@ @NCURSES_LIBS@ @PDCURSES_LIBS@ @WS2_LIBS@ \
		  @MATH_LIBS@ @SSL_LIBS@ @CRYPTO_LIBS@ lib/libgnu.a ccan/libccan.a \
		  $(LIBSECP256K1)


nxminer_CPPFLAGS = -I$(top_builddir)/lib -I$(top_srcdir)/lib -I$(top_builddir)/secp256k1/include \
 					@OPENCL_FLAGS@ $(CRYPTO_CFLAGS) $(SSL_CFLAGS) $(nxminer_INCLUDES)

if !HAVE_WINDOWS
nxminer_CPPFLAGS += @LIBCURL_CFLAGS@
endif

# common sources
nxminer_SOURCES := cgminer.c

nxminer_SOURCES	+= elist.h miner.h compat.h bench_block.h 		\
		   uint256.c uint256.h util.c util.h uthash.h logging.h \
		   sha2.c sha2.h api.c

nxminer_SOURCES	+= logging.c

if HAS_OPENCL
# GPU sources, TODO: make them selectable
# the GPU portion extracted from original main.c
nxminer_SOURCES += gpu/driver-opencl.h gpu/driver-opencl.c
# the original GPU related sources, unchanged
nxminer_SOURCES += gpu/ocl.c gpu/ocl.h gpu/findnonce.c gpu/findnonce.h
endif # HAS_OPENCL

if HAS_ADL
nxminer_SOURCES += gpu/adl.c gpu/adl.h gpu/adl_functions.h
endif # HAS_ADL
nxminer_SOURCES += *.cl

check-formatting:
	@echo "Checking source formatting style..."
	(./linter/clang-format.py check clang-format-12 `cat ./.formatted-files`)
