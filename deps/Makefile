_TOPDIR:=$(word 1, $(subst /deps, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

PKG_SUBDIRS +=libevent
PKG_SUBDIRS +=libcJSON
PKG_SUBDIRS +=libiniparser
PKG_SUBDIRS +=liblinenoise

include $(TOP_DIR)/default.mk

extra_all:
extra_clean:

