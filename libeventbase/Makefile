
_TOPDIR:=$(word 1, $(subst /libeventbase, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}
include $(TOP_DIR)/rules.mk

OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
FILTER_OUT = 
eventbase_OBJ = $(filter-out $(FILTER_OUT),$(OBJ_s))
test_OBJ = sample.o
eventbase_STATIC = libeventbase.a
eventbase_SHARED = libeventbase.so
eventbase_TEST = iniparser_test
LDFLAGS += 
test_LDFLAGS += -L. -l:libeventbase.a
CFLAGS += -fPIC 


all:shared static   install

shared:$(eventbase_SHARED) 
static:$(eventbase_STATIC) 
tests:$(eventbase_TEST)


%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)

#static libraries
$(eventbase_STATIC): $(eventbase_OBJ)
	@$(TARGET_AR) rcs $@ $(eventbase_OBJ)

#shared libraries 
$(eventbase_SHARED): $(eventbase_OBJ)
	@$(TARGET_CC) -shared -o $@ $(eventbase_OBJ) $(LDFLAGS) $(CFLAGS)

#test
$(eventbase_TEST):$(test_OBJ)
	@$(TARGET_CC) -o $@ $< $(LDFLAGS) $(CFLAGS) -I. $(test_LDFLAGS)

install:
	@$(INSTALL_DIR) $(TOP_DIR)/build/lib
	@$(INSTALL_DIR) $(TOP_DIR)/build/include
	@$(CP) $(eventbase_STATIC) $(TOP_DIR)/build/lib
	@$(CP) $(eventbase_SHARED) $(TOP_DIR)/build/lib
	@$(CP) *.h $(TOP_DIR)/build/include
	@$(call MESSAGE,"Finished!", "libeventbase")

clean:
	@rm -rf *.o  $(eventbase_STATIC) $(eventbase_SHARED)  $(eventbase_TEST)
	@$(call MESSAGE,"Clean!", "libeventbase")
