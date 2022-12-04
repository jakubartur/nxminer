package=dlfcn-win32
$(package)_version=1.3.1
$(package)_download_path=https://github.com/dlfcn-win32/dlfcn-win32/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=f7248a8baeb79d9bcd5f702cc08a777431708758e70d1730b59674c5e795e88a

define $(package)_set_vars
$(package)_config_opts=--disable-shared
$(package)_config_opts+=--disable-wine
$(package)_config_opts+=--enable-static
endef

define $(package)_config_cmds
  $($(package)_autoconf-dlfcn)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
