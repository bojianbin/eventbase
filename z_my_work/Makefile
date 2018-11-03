_TOPDIR:=$(word 1, $(subst /z_my_work, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

include ${TOP_DIR}/rules.mk

TARGET = event
TARGET_c = event_client
FILTER_OUT = ./test_client.o
OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
CFLAGS += 
LDFLAGS += -lpthread -l:libevent.a -lrt -l:libiniparser.a

OBJ=$(filter-out $(FILTER_OUT),$(OBJ_s))

all:target client

%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)
target:$(OBJ)
	@$(TARGET_CC) -o $(TARGET) $(OBJ) $(CFLAGS) $(LDFLAGS)
	@$(INSTALL_DIR) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", $(TARGET))
	
client:$(FILTER_OUT) ./anet.o
	@$(TARGET_CC) -o $(TARGET_c) $(FILTER_OUT) anet.o $(CFLAGS) $(LDFLAGS)

clean:
	@rm -rf *.o $(TARGET) $(TARGET_c)
	@$(call MESSAGE,"Clean!", $(TARGET))
