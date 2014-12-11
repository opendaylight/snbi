#
#  Sandeep Kumar Chawan S.
#  
#  Copyright (c) 2014 by cisco Systems, Inc.
#  All rights reserved.
#

BASE_DIR = ./linux
BASE_LINUX_AL_DIR = $(BASE_DIR)/src/linux_al
BASE_COMMON_DIR = $(BASE_DIR)/../common
BASE_AL_DIR = $(BASE_DIR)/../al
BASE_TOOLS_DIR = $(BASE_DIR)/tools
BASE_LIBCLI_DIR = $(BASE_TOOLS_DIR)/libcli
BASE_ANCLISIM_DIR = $(BASE_TOOLS_DIR)/snbi-sim
#BASE_LIBCLI_DIR = $(BASE_TOOLS_DIR)/libcli-internal
#BASE_ANCLISIM_DIR = $(BASE_TOOLS_DIR)/an-clisim-internal
BASE_LIBAVL_DIR = $(BASE_TOOLS_DIR)/libavl
AN_CLISIM_BIN=$(BASE_ANCLISIM_DIR)/bin
AN_CLISIM_OBJ=$(BASE_ANCLISIM_DIR)/obj
AN_CLISIM_SRC=$(BASE_ANCLISIM_DIR)/src
LD_LIB_PATH = /tmp/an_lib
AN_LD_LIB_PATH = ${LD_LIB_PATH}

CC_INCDIRS :=\
	-I$(BASE_LINUX_AL_DIR) \
	-I$(BASE_AL_DIR) \
	-I$(BASE_COMMON_DIR) \
	-I$(BASE_LIBCLI_DIR)/include \
	-I$(BASE_LIBAVL_DIR)/include \
	-I$(AN_CLISIM_SRC)

AN_LINUX_AL_SRC=$(BASE_LINUX_AL_DIR)
AN_LINUX_AL_OBJ=$(BASE_DIR)/obj
AN_LINUX_AL_BIN=$(BASE_DIR)/../bin

AN_COMMON_SRC=$(BASE_COMMON_DIR)
AN_COMMON_OBJ=$(BASE_COMMON_DIR)/obj_common

TOOLS_OBJ=$(BASE_LIBCLI_DIR)/obj
TOOLS_SRC=$(BASE_LIBCLI_DIR)/src

AVL_OBJ=$(BASE_LIBAVL_DIR)/obj

CC = gcc

DEBUG = -g
OPTIM = -O3
#CFLAGS = $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Werror -Wwrite-strings -Wformat

CFLAGS = -g

LD_FLAGS = -shared

LD_LIB = -lcrypt -lpthread -luuid -lrt

CC_AN_COMMON_OBJS :=\
	$(AN_COMMON_OBJ)/an_acp.o \
	$(AN_COMMON_OBJ)/an_anra.o \
	$(AN_COMMON_OBJ)/an_anra_db.o \
	$(AN_COMMON_OBJ)/an_bs.o \
	$(AN_COMMON_OBJ)/an.o \
	$(AN_COMMON_OBJ)/an_event_mgr.o \
	$(AN_COMMON_OBJ)/an_if_mgr.o \
	$(AN_COMMON_OBJ)/an_msg_mgr.o \
	$(AN_COMMON_OBJ)/an_nbr_db.o \
	$(AN_COMMON_OBJ)/an_nd.o \
	$(AN_COMMON_OBJ)/an_new.o \
	$(AN_COMMON_OBJ)/an_ni.o \
	$(AN_COMMON_OBJ)/an_tlv.o \
	$(AN_COMMON_OBJ)/an_topo_disc.o \
	$(AN_COMMON_OBJ)/an_util.o      

CC_AN_COMMON_SRCS :=\
	$(AN_COMMON_SRC)/an_acp.c \
	$(AN_COMMON_SRC)/an_anra.c \
	$(AN_COMMON_SRC)/an_anra_db.c \
	$(AN_COMMON_SRC)/an_bs.c \
	$(AN_COMMON_SRC)/an.c \
	$(AN_COMMON_SRC)/an_event_mgr.c \
	$(AN_COMMON_SRC)/an_if_mgr.c \
	$(AN_COMMON_SRC)/an_msg_mgr.c \
	$(AN_COMMON_SRC)/an_nbr_db.c \
	$(AN_COMMON_SRC)/an_nd.c \
	$(AN_COMMON_SRC)/an_new.c \
	$(AN_COMMON_SRC)/an_ni.c \
	$(AN_COMMON_SRC)/an_tlv.c \
	$(AN_COMMON_SRC)/an_topo_disc.c \
	$(AN_COMMON_SRC)/an_util.c

CC_AN_LINUX_AL_OBJS :=\
	$(AN_LINUX_AL_OBJ)/an_aaa_linux.o \
	$(AN_LINUX_AL_OBJ)/an_addr_linux.o \
	$(AN_LINUX_AL_OBJ)/an_avl_linux.o \
	$(AN_LINUX_AL_OBJ)/an_bitlist_linux.o \
	$(AN_LINUX_AL_OBJ)/an_cert_linux.o \
	$(AN_LINUX_AL_OBJ)/an_dike_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ether_linux.o \
	$(AN_LINUX_AL_OBJ)/an_file_linux.o \
	$(AN_LINUX_AL_OBJ)/an_http_linux.o \
	$(AN_LINUX_AL_OBJ)/an_icmp6_linux.o \
	$(AN_LINUX_AL_OBJ)/an_if_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ike_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ipsec_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ipv6_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ipv6_nd_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ipv6_send_linux.o \
	$(AN_LINUX_AL_OBJ)/an_key_linux.o \
	$(AN_LINUX_AL_OBJ)/an_l2_linux.o \
	$(AN_LINUX_AL_OBJ)/an_list_linux.o \
	$(AN_LINUX_AL_OBJ)/an_logger_linux.o \
	$(AN_LINUX_AL_OBJ)/an_mem_guard_linux.o \
	$(AN_LINUX_AL_OBJ)/an_mem_linux.o \
	$(AN_LINUX_AL_OBJ)/an_misc_linux.o \
	$(AN_LINUX_AL_OBJ)/an_ntp_linux.o \
	$(AN_LINUX_AL_OBJ)/an_pak_linux.o \
	$(AN_LINUX_AL_OBJ)/an_proc_linux.o \
	$(AN_LINUX_AL_OBJ)/an_routing_linux.o \
	$(AN_LINUX_AL_OBJ)/an_service_discovery_linux.o \
	$(AN_LINUX_AL_OBJ)/an_sign_linux.o \
	$(AN_LINUX_AL_OBJ)/an_str_linux.o \
	$(AN_LINUX_AL_OBJ)/an_sudi_linux.o \
	$(AN_LINUX_AL_OBJ)/an_syslog_linux.o \
	$(AN_LINUX_AL_OBJ)/an_timer_linux.o \
	$(AN_LINUX_AL_OBJ)/an_tunnel_linux.o \
	$(AN_LINUX_AL_OBJ)/an_udp_linux.o \

CC_AN_LINUX_AL_SRCS :=\
	$(AN_LINUX_AL_SRC)/an_aaa_linux.c \
	$(AN_LINUX_AL_SRC)/an_addr_linux.c \
	$(AN_LINUX_AL_SRC)/an_avl_linux.c \
	$(AN_LINUX_AL_SRC)/an_bitlist_linux.c \
	$(AN_LINUX_AL_SRC)/an_cert_linux.c \
	$(AN_LINUX_AL_SRC)/an_dike_linux.c \
	$(AN_LINUX_AL_SRC)/an_ether_linux.c \
	$(AN_LINUX_AL_SRC)/an_file_linux.c\
	$(AN_LINUX_AL_SRC)/an_http_linux.c\
	$(AN_LINUX_AL_SRC)/an_icmp6_linux.c\
	$(AN_LINUX_AL_SRC)/an_if_linux.c \
	$(AN_LINUX_AL_SRC)/an_ike_linux.c \
	$(AN_LINUX_AL_SRC)/an_ipsec_linux.c\
	$(AN_LINUX_AL_SRC)/an_ipv6_linux.c      \
	$(AN_LINUX_AL_SRC)/an_ipv6_nd_linux.c \
	$(AN_LINUX_AL_SRC)/an_ipv6_send_linux.c\
	$(AN_LINUX_AL_SRC)/an_key_linux.c \
	$(AN_LINUX_AL_SRC)/an_l2_linux.c \
	$(AN_LINUX_AL_SRC)/an_list_linux.c      \
	$(AN_LINUX_AL_SRC)/an_logger_linux.c\
	$(AN_LINUX_AL_SRC)/an_mem_guard_linux.c\
	$(AN_LINUX_AL_SRC)/an_mem_linux.c \
	$(AN_LINUX_AL_SRC)/an_misc_linux.c \
	$(AN_LINUX_AL_SRC)/an_ntp_linux.c \
	$(AN_LINUX_AL_SRC)/an_pak_linux.c \
	$(AN_LINUX_AL_SRC)/an_proc_linux.c \
	$(AN_LINUX_AL_SRC)/an_routing_linux.c \
	$(AN_LINUX_AL_SRC)/an_service_discovery_linux.c \
	$(AN_LINUX_AL_SRC)/an_sign_linux.c\
	$(AN_LINUX_AL_SRC)/an_str_linux.c \
	$(AN_LINUX_AL_SRC)/an_sudi_linux.c \
	$(AN_LINUX_AL_SRC)/an_syslog_linux.c \
	$(AN_LINUX_AL_SRC)/an_timer_linux.c \
	$(AN_LINUX_AL_SRC)/an_tunnel_linux.c \
	$(AN_LINUX_AL_SRC)/an_udp_linux.c

CC_LIBCLI_OBJS :=\
	$(TOOLS_OBJ)/libcli.o

CC_LIBAVL_OBJS :=\
	$(AVL_OBJ)/libavl.o

CC_AN_CLISIM_SRCS :=\
	$(AN_CLISIM_SRC)/an_cli.c \
	$(AN_CLISIM_SRC)/show_an.c \
	$(AN_CLISIM_SRC)/an_clisim_test.c \
	$(AN_CLISIM_SRC)/conf_an.c

all: mkdir libcli.o libavl.o an_linux_al.o an_common.o

mkdir:
	echo "Making obj dir"
	mkdir -p $(AN_LD_LIB_PATH)
	mkdir -p $(AN_LINUX_AL_OBJ)
	mkdir -p $(AN_COMMON_OBJ)
	mkdir -p $(AN_LINUX_AL_BIN)
	@echo ' '

libcli.o:
	make -f $(BASE_TOOLS_DIR)/libcli-internal.mk
	mv $(TOOLS_OBJ)/$@ ${AN_LD_LIB_PATH}
                
libavl.o:
	make -f $(BASE_LIBAVL_DIR)/libavl.mk
	mv $(AVL_OBJ)/$@ ${AN_LD_LIB_PATH}

an_linux_al.o: $(CC_AN_LINUX_AL_SRCS)
	@echo "Building target: $@"
	$(CC) -o $(AN_LINUX_AL_OBJ)/$@ $^ $(CC_INCDIRS) $(CFLAGS) \
	$(LD_LIB) $(LD_FLAGS) -fPIC
	mv $(AN_LINUX_AL_OBJ)/$@ ${AN_LD_LIB_PATH}

an_common.o: $(CC_AN_COMMON_SRCS) $(CC_AN_CLISIM_SRCS) $(AN_LD_LIB_PATH)/an_linux_al.o $(AN_LD_LIB_PATH)/libcli.o $(AN_LD_LIB_PATH)/libavl.o
	@echo "Building target: $@"
	$(CC) -o $(AN_COMMON_OBJ)/snbi-sim $^ $(CC_INCDIRS) $(CFLAGS) \
	$(LD_LIB) -fPIC
	mv $(AN_COMMON_OBJ)/snbi-sim ${AN_LINUX_AL_BIN}
	@echo ' **SUCCESS**- Finished building target: SNBI FE APP'

#an_clisim: $(CC_AN_CLISIM_SRCS) $(AN_LD_LIB_PATH)/an_linux_al.o $(AN_LD_LIB_PATH)/an_common.o $(AN_LD_LIB_PATH)/libcli.o $(AN_LD_LIB_PATH)/libavl.o
#	@echo "Building target: $@"
#	$(CC) -o $(AN_LINUX_AL_BIN)/$@ $^ $(CC_INCDIRS) $(CFLAGS)
#	@echo 'Finished building target: $@'
#	@echo ' '

clean:
	@echo "Cleaning obj and bin dir"
	rm -rf $(TOOLS_OBJ)
	rm -rf $(AVL_OBJ)
	rm -rf $(AN_CLISIM_OBJ)
	rm -rf $(AN_LINUX_AL_OBJ)
	rm -rf $(AN_COMMON_OBJ)
	rm -rf $(AN_CLISIM_BIN)
	rm -rf $(AN_LINUX_AL_BIN)

