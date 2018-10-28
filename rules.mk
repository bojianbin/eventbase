
#for example
#arm-hisiv300-linux- 	(if hisi)
#- 						(if gcc)
TARGET_CROSS_COMPILE:=-






TARGET_HOST:=$(patsubst %-,%,$(TARGET_CROSS_COMPILE))


TARGET_CC:=$(patsubst -%,%,$(TARGET_CROSS_COMPILE)gcc)
TARGET_AR:=$(patsubst -%,%,$(TARGET_CROSS_COMPILE)ar)
TARGET_RANLIB:=$(patsubst -%,%,$(TARGET_CROSS_COMPILE)ranlib)
TARGET_CXX:=$(patsubst -%,%,$(TARGET_CROSS_COMPILE)g++)
CC:=$(TARGET_CC)
AR:=$(TARGET_AR)
RANLIB:=$(TARGET_RANLIB)
CXX:=$(TARGET_CXX)

CP:=cp -fpR
LN:=ln -sf
TAR:=tar
XARGS:=xargs -r

INSTALL_BIN:=install -m0755
INSTALL_DIR:=install -d -m0755
INSTALL_DATA:=install -m0644
INSTALL_CONF:=install -m0600

CFLAGS = -I$(TOP_DIR)/build/include
LDFLAGS = -L$(TOP_DIR)/build/lib

TERM_BOLD := $(shell tput smso 2>/dev/null)
TERM_RESET := $(shell tput rmso 2>/dev/null)
MESSAGE = echo "$(TERM_BOLD)>>> $(1) $(2) $(TERM_RESET)"
