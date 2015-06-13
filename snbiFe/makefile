#
#  Sandeep Kumar Chawan S.
#  
#  Copyright (c) 2014 by cisco Systems, Inc.
#  All rights reserved.
# This program and the accompanying materials are made available under
# the terms of the Eclipse License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
#

BASE_DIR = .
BASE_LINUX_AL_DIR = $(BASE_DIR)/impl
BASE_COMMON_DIR = $(BASE_DIR)/common
BASE_AL_DIR = $(BASE_DIR)/al
BASE_LIB_DIR = $(BASE_DIR)/lib
BASE_SNBI_CLISIM_DIR = $(BASE_DIR)/simulator
BASE_TOOLS_DIR = $(BASE_DIR)/tools

BASE_OLIBC_AVL_DIR = $(BASE_LIB_DIR)/olibc_avl
BASE_OLIBC_LIST_DIR = $(BASE_LIB_DIR)/olibc_list
BASE_OLIBC_EVENT_DIR= $(BASE_LIB_DIR)/olibc_event
BASE_OLIBC_CLI_DIR = $(BASE_LIB_DIR)/olibc_cliParser
BASE_OLIBC_COMMON_DIR = $(BASE_LIB_DIR)/olibc_common
BASE_OLIBC_HASH_DIR = $(BASE_LIB_DIR)/olibc_hash
BASE_OLIBC_NET_DIR = $(BASE_LIB_DIR)/olibc_net
BASE_OLIBC_LOG_DIR = $(BASE_LIB_DIR)/olibc_log


SNBI_BIN=$(BASE_DIR)/bin
SNBI_OBJ=$(BASE_DIR)/obj

CLI_PARSER_DIR = $(BASE_TOOLS_DIR)/cli-parser-gen

CC_OLIBC_INCDIRS :=\
	-I$(BASE_OLIBC_COMMON_DIR)/inc \
	-I$(BASE_OLIBC_CLI_DIR)/inc \
	-I$(BASE_OLIBC_AVL_DIR)/inc \
	-I$(BASE_OLIBC_LIST_DIR)/inc \
	-I$(BASE_OLIBC_HASH_DIR)/inc \
	-I$(BASE_OLIBC_EVENT_DIR)/inc \
	-I$(BASE_OLIBC_NET_DIR)/inc \
	-I$(BASE_OLIBC_LOG_DIR)/inc \

CC_SNBI_INCDIRS :=\
	$(CC_OLIBC_INCDIRS) \
	-I$(BASE_LINUX_AL_DIR) \
	-I$(BASE_AL_DIR) \
	-I$(BASE_COMMON_DIR) \

SNBI_COMMON_SRC=$(BASE_COMMON_DIR)
SNBI_LINUX_AL_SRC=$(BASE_LINUX_AL_DIR)
SNBI_CLISIM_SRC=$(BASE_SNBI_CLISIM_DIR)/src

OLIBC_CLI_SRC=$(BASE_OLIBC_CLI_DIR)/src
OLIBC_AVL_SRC=$(BASE_OLIBC_AVL_DIR)/src
OLIBC_LIST_SRC=$(BASE_OLIBC_LIST_DIR)/src
OLIBC_EVENT_SRC=$(BASE_OLIBC_EVENT_DIR)/src
OLIBC_COMMON_SRC=$(BASE_OLIBC_COMMON_DIR)/src
OLIBC_HASH_SRC=$(BASE_OLIBC_HASH_DIR)/src
OLIBC_NET_SRC=$(BASE_OLIBC_NET_DIR)/src


CC = gcc

#DEBUG = -g
#OPTIM = -O3
#CFLAGS = $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Werror -Wwrite-strings -Wformat

CFLAGS = -g -Wuninitialized -Wreturn-type \
	-Wunused-label -Wunused-value -Wunused-variable \
	-Wimplicit-function-declaration -Wimplicit-int -Wmissing-braces \
	-Wnonnull -Wparentheses

#OLIBC_LD_LIB = -lpthread -levent -levent_pthreads
OLIBC_LD_LIB = -levent -levent_pthreads

#LD_LIB = -lcrypt -lpthread -lrt
LD_LIB = -lcrypt $(OLIBC_LD_LIB)

CC_SNBI_COMMON_SRCS :=\
	$(SNBI_COMMON_SRC)/an_acp.c \
	$(SNBI_COMMON_SRC)/an_acp_cnp.c \
	$(SNBI_COMMON_SRC)/an_acp_ntp.c \
	$(SNBI_COMMON_SRC)/an_anra.c \
	$(SNBI_COMMON_SRC)/an_bs.c \
	$(SNBI_COMMON_SRC)/an_cd.c \
	$(SNBI_COMMON_SRC)/an_config_download.c \
	$(SNBI_COMMON_SRC)/an.c \
	$(SNBI_COMMON_SRC)/an_event_mgr.c \
	$(SNBI_COMMON_SRC)/an_event_mgr_db.c \
	$(SNBI_COMMON_SRC)/an_idp.c \
	$(SNBI_COMMON_SRC)/an_if_mgr.c \
	$(SNBI_COMMON_SRC)/an_intent.c \
	$(SNBI_COMMON_SRC)/an_msg_mgr.c \
	$(SNBI_COMMON_SRC)/an_nbr_db.c \
	$(SNBI_COMMON_SRC)/an_nd.c \
	$(SNBI_COMMON_SRC)/an_new.c \
	$(SNBI_COMMON_SRC)/an_ni.c \
	$(SNBI_COMMON_SRC)/an_srvc.c \
	$(SNBI_COMMON_SRC)/an_srvc_db.c \
	$(SNBI_COMMON_SRC)/an_tlv.c \
	$(SNBI_COMMON_SRC)/an_util.c


CC_SNBI_LINUX_AL_SRCS :=\
	$(SNBI_LINUX_AL_SRC)/an_aaa_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_addr_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_avl_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_bitlist_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_cert_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_dike_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ether_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_file_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_http_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_icmp6_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_if_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ike_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ipsec_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ipv6_linux.c  \
	$(SNBI_LINUX_AL_SRC)/an_ipv6_nd_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ipv6_send_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_key_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_l2_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_list_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_logger_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_mem_guard_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_mem_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_misc_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_ntp_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_pak_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_proc_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_routing_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_service_discovery_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_sign_linux.c\
	$(SNBI_LINUX_AL_SRC)/an_str_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_sudi_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_syslog_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_timer_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_tunnel_linux.c \
	$(SNBI_LINUX_AL_SRC)/an_udp_linux.c

CC_SNBI_CLISIM_SRCS :=\
	$(SNBI_CLISIM_SRC)/an_clisim_conf.c \
	$(SNBI_CLISIM_SRC)/an_clisim_avl_test.c \
	$(SNBI_CLISIM_SRC)/an_clisim_list_test.c \
	$(SNBI_CLISIM_SRC)/an_clisim_hash_test.c \
	$(SNBI_CLISIM_SRC)/an_clisim_event_test.c \
	$(SNBI_CLISIM_SRC)/an_clisim_show.c \
	$(SNBI_CLISIM_SRC)/an_clisim_debug.c \
	$(SNBI_CLISIM_SRC)/an_clisim_logg.c \
	$(SNBI_CLISIM_SRC)/an_clisim_net_test.c \
	$(SNBI_CLISIM_SRC)/an_clisim.c

CC_OLIBC_CLI_SRCS :=\
	$(OLIBC_CLI_SRC)/cparser.c \
	$(OLIBC_CLI_SRC)/cparser_token.c \
	$(OLIBC_CLI_SRC)/cparser_token_tbl.c \
	$(OLIBC_CLI_SRC)/cparser_token_tbl.c \
	$(OLIBC_CLI_SRC)/cparser_io_unix.c \
	$(OLIBC_CLI_SRC)/cparser_line.c \
	$(OLIBC_CLI_SRC)/cparser_fsm.c \
	$(OLIBC_CLI_SRC)/cparser_tree.c

CC_OLIBC_COMMON_SRCS := $(OLIBC_COMMON_SRC)/olibc_common.c \
	$(OLIBC_COMMON_SRC)/olibc_mem.c

CC_OLIBC_LIST_SRCS := $(OLIBC_LIST_SRC)/olibc_list.c

CC_OLIBC_AVL_SRCS := $(OLIBC_AVL_SRC)/olibc_avl.c

CC_OLIBC_EVENT_SRCS := $(OLIBC_EVENT_SRC)/olibc_pthread.c \
	$(OLIBC_EVENT_SRC)/olibc_timer.c \
	$(OLIBC_EVENT_SRC)/olibc_msg_q.c

CC_OLIBC_HASH_SRCS := $(OLIBC_HASH_SRC)/olibc_hash.c

CC_OLIBC_NET_SRCS := $(OLIBC_NET_SRC)/olibc_if_rt_netlink.c \
	$(OLIBC_NET_SRC)/olibc_addr_rt_netlink.c \
	$(OLIBC_NET_SRC)/olibc_rt_netlink.c \
	$(OLIBC_NET_SRC)/olibc_netlink.c

CC_OLIBC_ALL_SRCS :=\
	$(CC_OLIBC_COMMON_SRCS) \
	$(CC_OLIBC_LIST_SRCS) \
	$(CC_OLIBC_AVL_SRCS) \
	$(CC_OLIBC_CLI_SRCS) \
	$(CC_OLIBC_HASH_SRCS) \
	$(CC_OLIBC_EVENT_SRCS) \
	$(CC_OLIBC_NET_SRCS) \

CC_ALL_SRCS := $(CC_OLIBC_ALL_SRCS) \
	$(CC_SNBI_LINUX_AL_SRCS) \
	$(CC_SNBI_COMMON_SRCS) \


all: mkdir libolibc an_linux_al an_common snbi_clisim

mkdir:
	echo "Making obj dir"
	mkdir -p $(SNBI_BIN)
	mkdir -p $(SNBI_OBJ)
	@echo ' '

parser:
	echo "Building target: $@"
	cd $(CLI_PARSER_DIR)
	./mk_parser.py clisim.cli

libolibc: $(CC_OLIBC_ALL_SRCS)
	echo "Building target: $@" 
	$(CC) -c $^ $(CC_SNBI_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)
                
an_linux_al: $(CC_SNBI_LINUX_AL_SRCS)
	@echo "Building target: $@"
	$(CC) -c $^ $(CC_SNBI_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)

an_common: $(CC_SNBI_COMMON_SRCS)
	@echo "Building target: $@"
	$(CC) -c $^ $(CC_SNBI_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)

snbi_clisim: $(CC_SNBI_CLISIM_SRCS) $(CC_ALL_SRCS)
	@echo "Building target: $@"
	$(CC) -c $(CC_SNBI_CLISIM_SRCS) $(CC_SNBI_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)
	$(CC) -o $(SNBI_BIN)/$@ $(SNBI_OBJ)/*.o $(LD_LIB)
	@echo 'Finished building target: $@'
	@echo ' '

clean:
	@echo "Cleaning obj and bin dir"
	rm -rf $(SNBI_BIN)
	rm -rf $(SNBI_OBJ)
	rm -rf *.o
