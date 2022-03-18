# Some modules should be built and distributed, e.g. openvswitch.
#
# Some modules should be built but not distributed, e.g. third-party
# hwtable modules.
build_multi_modules = \
	brcompat
both_modules = \
	$(build_multi_modules)

# When changing the name of 'build_modules', please also update the
# print-build-modules in Makefile.am.
build_modules = $(both_modules)	# Modules to build
dist_modules = $(both_modules)	# Modules to distribute

brcompat_sources = linux/compat/genetlink-brcompat.c brcompat_main.c
brcompat_headers =

dist_sources = $(foreach module,$(dist_modules),$($(module)_sources))
dist_headers = $(foreach module,$(dist_modules),$($(module)_headers))
dist_extras = $(foreach module,$(dist_modules),$($(module)_extras))
build_sources = $(foreach module,$(build_modules),$($(module)_sources))
build_headers = $(foreach module,$(build_modules),$($(module)_headers))
build_links = $(notdir $(build_sources))
build_objects = $(notdir $(patsubst %.c,%.o,$(build_sources)))
