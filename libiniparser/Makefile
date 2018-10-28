
_TOPDIR:=$(word 1, $(subst /libiniparser, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}
include $(TOP_DIR)/rules.mk

OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
FILTER_OUT = ./sample.o 
INI_OBJ = $(filter-out $(FILTER_OUT),$(OBJ_s))
test_OBJ = sample.o
INI_STATIC = libiniparser.a
INI_SHARED = libiniparser.so
INI_TEST = iniparser_test
LDFLAGS += 
test_LDFLAGS += -L. -l:libiniparser.a
CFLAGS += -fPIC 


all:shared static tests install

shared:$(INI_SHARED) 
static:$(INI_STATIC) 
tests:$(INI_TEST)


%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)

#static libraries
$(INI_STATIC): $(INI_OBJ)
	@$(TARGET_AR) rcs $@ $(INI_OBJ)

#shared libraries 
$(INI_SHARED): $(INI_OBJ)
	@$(TARGET_CC) -shared -o $@ $(INI_OBJ) $(LDFLAGS) $(CFLAGS)

#test
$(INI_TEST):$(test_OBJ)
	@$(TARGET_CC) -o $@ $< $(LDFLAGS) $(CFLAGS) -I. $(test_LDFLAGS)

install:
	@$(INSTALL_DIR) $(TOP_DIR)/build/lib
	@$(INSTALL_DIR) $(TOP_DIR)/build/include
	@$(CP) $(INI_STATIC) $(TOP_DIR)/build/lib
	@$(CP) $(INI_SHARED) $(TOP_DIR)/build/lib
	@$(CP) *.h $(TOP_DIR)/build/include
	@$(CP) $(INI_TEST) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", "libiniparser")

clean:
	@rm -rf *.o  $(INI_STATIC) $(INI_SHARED)  $(INI_TEST)
	@$(call MESSAGE,"Clean!", "libiniparser")
