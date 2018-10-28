_TOPDIR:=$(word 1, $(subst /libevent, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

TARGET=libevent-2.1.8-stable
include $(TOP_DIR)/rules.mk
BUILD_DIR=$(TOP_DIR)/build/
EVENT_DIR=$(TOP_DIR)/libevent/$(TARGET)

all:prepare compile install

prepare:
ifeq ($(wildcard $(EVENT_DIR)),)
	tar -zxf $(TARGET).tar.gz 
	cd libevent-2.1.8-stable && ./configure --prefix=$(BUILD_DIR) \
		--enable-shared \
		--enable-static \
		--build=$(shell uname -m)-linux-gnu \
		--host=$(TARGET_HOST) \
		--target=$(TARGET_HOST) 
endif
compile:
	@make -C $(TARGET)
	
install:
	@make -C $(TARGET) install
	@$(call MESSAGE,"Finished!", $(TARGET))

clean:
	@rm -rf $(TARGET)
	@$(call MESSAGE,"Clean!", $(TARGET))
