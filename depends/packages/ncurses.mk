package=ncurses
$(package)_version=6.3
$(package)_download_path=https://invisible-mirror.net/archives/ncurses/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=97fc51ac2b085d4cde31ef4d2c3122c21abc217e9090a43a30fc5ec21684e059

define $(package)_set_vars
$(package)_config_opts=--disable-getcap
$(package)_config_opts+=--disable-getcap-cache
$(package)_config_opts+=--disable-termcap
$(package)_config_opts+=--disable-shared
$(package)_config_opts+=--enable-database
$(package)_config_opts+=--enable-db-install
$(package)_config_opts+=--enable-ext-funcs
$(package)_config_opts+=--disable-hard-tabs
$(package)_config_opts+=--enable-pc-files
$(package)_config_opts+=--enable-sp-funcs
$(package)_config_opts+=--with-database=$($(package)_terminfo_dir)/terminfo.src
$(package)_config_opts+=--with-normal
$(package)_config_opts+=--without-ada
$(package)_config_opts+=--without-cxx
$(package)_config_opts+=--without-cxx-binding
$(package)_config_opts+=--without-debug
$(package)_config_opts+=--without-manpages
$(package)_config_opts+=--without-progs
$(package)_config_opts_linux+=--with-termlib
$(package)_config_opts_linux+=--with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo
$(package)_config_opts_mingw32+=--disable-stripping
$(package)_config_opts_mingw32+=--enable-exp-win32
$(package)_config_opts_mingw32+=--enable-term-driver
$(package)_config_opts_mingw32+=--disable-home-terminfo
$(package)_config_opts_mingw32+=--with-fallback=ms-terminal
$(package)_config_opts_mingw32+=--without-libtool
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
