# These python files are used at build time but not runtime,
# so they are not installed.
EXTRA_DIST += \
	python/build/__init__.py \
	python/build/soutil.py

# PyPI support.
EXTRA_DIST += \
	python/README.rst \
	python/setup.py

FLAKE8_PYFILES += \
	python/setup.py \
	python/build/__init__.py \
	python/ovs/dirs.py.template

