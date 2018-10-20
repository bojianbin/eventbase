
_TOPDIR:=$(word 1, $(subst /libcJSON, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}
include $(TOP_DIR)/rules.mk

LIBVERSION = 1.7.8
CJSON_OBJ = cJSON.o
UTILS_OBJ = cJSON_Utils.o
test_OBJ = test.o
CJSON_STATIC = libcjson.a
UTILS_STATIC = libcjson_utils.a
CJSON_SHARED = libcjson.so
UTILS_SHARED = libcjson_utils.so
CJSON_TEST = cJSON_test
cJSON_INCLUDE = cJSON.h 
UTILS_INCLUDE = cJSON_Utils.h
LDFLAGS += 
test_LDFLAGS += -L. -l:libcjson.a
CFLAGS += -fPIC


all:shared static tests install

shared:$(CJSON_SHARED) $(UTILS_SHARED)
static:$(CJSON_STATIC) $(UTILS_STATIC)
tests:$(CJSON_TEST)


%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)

#static libraries
#cJSON
$(CJSON_STATIC): $(CJSON_OBJ)
	@$(TARGET_AR) rcs $@ $<
#cJSON_Utils
$(UTILS_STATIC): $(UTILS_OBJ)
	@$(TARGET_AR) rcs $@ $<

#shared libraries .so.1.0.0
#cJSON
$(CJSON_SHARED): $(CJSON_OBJ)
	@$(TARGET_CC) -shared -o $@ $< $(LDFLAGS) $(CFLAGS)
#cJSON_Utils
$(UTILS_SHARED): $(UTILS_OBJ)
	@$(TARGET_CC) -shared -o $@ $< $(LDFLAGS) $(CFLAGS)

#test
$(CJSON_TEST):$(test_OBJ)
	@$(TARGET_CC) -o $@ $< $(LDFLAGS) $(CFLAGS) -I. $(test_LDFLAGS)

install:
	@$(INSTALL_DIR) $(TOP_DIR)/build/lib
	@$(INSTALL_DIR) $(TOP_DIR)/build/include
	@$(CP) $(CJSON_STATIC) $(TOP_DIR)/build/lib
	@$(CP) $(UTILS_STATIC) $(TOP_DIR)/build/lib
	@$(CP) $(CJSON_SHARED) $(TOP_DIR)/build/lib
	@$(CP) $(UTILS_SHARED) $(TOP_DIR)/build/lib
	@$(CP) $(cJSON_INCLUDE) $(TOP_DIR)/build/include
	@$(CP) $(UTILS_INCLUDE) $(TOP_DIR)/build/include
	@$(CP) $(CJSON_TEST) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", "libcJSON")

clean:
	@rm -rf *.o $(CJSON_TEST) $(CJSON_STATIC) $(CJSON_SHARED) $(UTILS_STATIC) $(UTILS_SHARED) $(CJSON_TEST)
	@$(call MESSAGE,"Clean!", "libcJSON")
