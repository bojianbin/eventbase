_TOPDIR:=$(word 1, $(subst /z_my_work, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

include ${TOP_DIR}/rules.mk

TARGET = event
TARGET_c = eventbase_test
TARGET_c2 = eventbase_client
FILTER_OUT = ./eventbase_test.o ./eventbase_client.o
OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
CFLAGS += 
LDFLAGS +=  -l:libevent.a -lrt  -l:libeventbase.a -l:libiniparser.a -l:libcjson.a -l:liblinenoise.a -lpthread

OBJ=$(filter-out $(FILTER_OUT),$(OBJ_s))

all:target client install 

%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)
target:$(OBJ)
	@$(TARGET_CC) -o $(TARGET) $(OBJ) $(CFLAGS) $(LDFLAGS)
	
client:$(FILTER_OUT) 
	@$(TARGET_CC) -o $(TARGET_c) ./eventbase_test.o  $(CFLAGS) $(LDFLAGS)
	@$(TARGET_CC) -o $(TARGET_c2) ./eventbase_client.o  $(CFLAGS) $(LDFLAGS)


install:
	@$(INSTALL_DIR) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET_c) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET_c2) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", $(TARGET))
	
clean:
	@rm -rf *.o $(TARGET) $(TARGET_c) $(TARGET_c2)
	@$(call MESSAGE,"Clean!", $(TARGET))
