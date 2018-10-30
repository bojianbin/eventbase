_TOPDIR:=$(word 1, $(subst /z_my_work, ,$(shell pwd)))
TOP_DIR:=${_TOPDIR}

include ${TOP_DIR}/rules.mk

TARGET = event
FILTER_OUT = 
OBJ_s = $(patsubst %.c,%.o,$(wildcard ./*.c))
CFLAGS += 
LDFLAGS += -lpthread -l:libevent.a -lrt -l:libiniparser.a

OBJ=$(filter-out $(FILTER_OUT),$(OBJ_s))


%.o:%.c
	@$(TARGET_CC) -o $@ -c $<  $(CFLAGS)
all:$(OBJ)
	@$(TARGET_CC) -o $(TARGET) $(OBJ) $(CFLAGS) $(LDFLAGS)
	@$(INSTALL_DIR) $(TOP_DIR)/build/bin
	@$(CP) $(TARGET) $(TOP_DIR)/build/bin
	@$(call MESSAGE,"Finished!", $(TARGET))
clean:
	@rm -rf *.o $(TARGET) 
	@$(call MESSAGE,"Clean!", $(TARGET))
