package=curl
$(package)_version=7.86.0
$(package)_download_path=https://curl.se/download
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=f5ca69db03eea17fa8705bdfb1a9f58d76a46c9010518109bb38f313137e0a28

$(package)_dependencies=openssl

define $(package)_set_vars
$(package)_config_opts=--with-openssl
$(package)_config_opts+=--disable-shared
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
