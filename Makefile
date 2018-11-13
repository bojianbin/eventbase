PKG_SUBDIRS +=deps
PKG_SUBDIRS +=libeventbase
PKG_SUBDIRS +=z_my_work


include default.mk

extra_all:
extra_clean:
	@rm -rf build