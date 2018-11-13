_TOPDIR:=$(word 1, $(subst /deps/liblinenoise, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}
include $(TOP_DIR)/rules.mk

OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
FILTER_OUT = ./example.o 
noise_OBJ = $(filter-out $(FILTER_OUT),$(OBJ_s))
test_OBJ = example.o
noise_STATIC = liblinenoise.a
noise_SHARED = liblinenoise.so
noise_TEST = linenoise_test
LDFLAGS += 
test_LDFLAGS += -L. -l:liblinenoise.a
CFLAGS += -fPIC 


all:shared static  tests install

shared:$(noise_SHARED) 
static:$(noise_STATIC) 
tests:$(noise_TEST)


%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)

#static libraries
$(noise_STATIC): $(noise_OBJ)
	@$(TARGET_AR) rcs $@ $(noise_OBJ)

#shared libraries 
$(noise_SHARED): $(noise_OBJ)
	@$(TARGET_CC) -shared -o $@ $(noise_OBJ) $(LDFLAGS) $(CFLAGS)

#test
$(noise_TEST):$(test_OBJ)
	@$(TARGET_CC) -o $@ $< $(LDFLAGS) $(CFLAGS) -I. $(test_LDFLAGS)

install:
	@$(INSTALL_DIR) $(TOP_DIR)/build/lib
	@$(INSTALL_DIR) $(TOP_DIR)/build/include
	@$(CP) $(noise_STATIC) $(TOP_DIR)/build/lib
	@$(CP) $(noise_SHARED) $(TOP_DIR)/build/lib
	@$(CP) *.h $(TOP_DIR)/build/include
	@$(CP) $(noise_TEST) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", "liblinenoise")

clean:
	@rm -rf *.o  $(noise_STATIC) $(noise_SHARED)  $(noise_TEST)
	@$(call MESSAGE,"Clean!", "liblinenoise")

