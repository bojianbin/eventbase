_TOPDIR:=$(word 1, $(subst /deps/libevent, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

TARGET=libevent-2.1.8-stable
TARGET_test=libevent_test
OBJ_test = sample.o
include $(TOP_DIR)/rules.mk
BUILD_DIR=$(TOP_DIR)/build/
EVENT_DIR=$(TOP_DIR)/deps/libevent/$(TARGET)

all:prepare compile  install test

sample.o:sample.c
	@$(TARGET_CC) -c  sample.c -I$(TARGET)/include
	
prepare:
ifeq ($(wildcard $(EVENT_DIR)),)
	tar -zxf $(TARGET).tar.gz 
	cd libevent-2.1.8-stable && ./configure --prefix=$(BUILD_DIR) \
		--disable-openssl \
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
	
	
test:$(OBJ_test)
	@$(TARGET_CC) -o $(TARGET_test) $(OBJ_test) $(LDFLAGS) $(CFLAGS) -l:libevent.a -lrt
	@$(INSTALL_DIR) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET_test) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", $(TARGET))
	
clean:
	@rm -rf $(TARGET) $(TARGET_test) *.o
	@$(call MESSAGE,"Clean!", $(TARGET))
