package=ocl-icd
$(package)_version=2.3.1
$(package)_download_path=https://github.com/OCL-dev/ocl-icd/archive/refs/tags/
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=a32b67c2d52ffbaf490be9fc18b46428ab807ab11eff7664d7ff75e06cfafd6d

ifeq ($(host_os),mingw32)
$(package)_dependencies=dlfcn-win32
endif

define $(package)_set_vars
$(package)_config_opts=--enable-official-khronos-headers
$(package)_config_opts+=--enable-pthread-once
$(package)_config_opts+=--enable-static
$(package)_config_opts+=--disable-debug
endef

define $(package)_config_cmds
  ./bootstrap && ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
endef
