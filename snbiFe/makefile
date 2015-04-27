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
BASE_LINUX_AL_DIR = $(BASE_DIR)/infra/impl
BASE_COMMON_DIR = $(BASE_DIR)/common
BASE_AL_DIR = $(BASE_DIR)/al
BASE_LIB_DIR = $(BASE_DIR)/infra/lib
BASE_SNBI_CLISIM_DIR = $(BASE_LIB_DIR)/simulator
BASE_OLIBAVL_DIR = $(BASE_LIB_DIR)/olibc_avl
BASE_OLIBLIST_DIR = $(BASE_LIB_DIR)/olibc_list
BASE_OLIBEVENT_DIR= $(BASE_LIB_DIR)/olibc_event
BASE_OLIBCLI_DIR = $(BASE_LIB_DIR)/olibc_cliParser
BASE_OLIBCOMMON_DIR = $(BASE_LIB_DIR)/olibc_common
SNBI_BIN=$(BASE_DIR)/bin
SNBI_OBJ=$(BASE_DIR)/obj

CC_INCDIRS :=\
	-I$(BASE_LINUX_AL_DIR) \
	-I$(BASE_AL_DIR) \
	-I$(BASE_COMMON_DIR) \
	-I$(BASE_OLIBCLI_DIR)/inc \
	-I$(BASE_OLIBAVL_DIR)/inc \
	-I$(BASE_OLIBLIST_DIR)/inc \
	-I$(BASE_OLIBEVENT_DIR)/inc \
	-I$(BASE_OLIBCOMMON_DIR)/inc \

SNBI_COMMON_SRC=$(BASE_COMMON_DIR)
SNBI_LINUX_AL_SRC=$(BASE_LINUX_AL_DIR)
SNBI_CLISIM_SRC=$(BASE_SNBI_CLISIM_DIR)
SNBI_LIBCLI_SRC=$(BASE_OLIBCLI_DIR)/src
SNBI_LIBAVL_SRC=$(BASE_OLIBAVL_DIR)/src
SNBI_LIBLIST_SRC=$(BASE_OLIBLIST_DIR)/src
SNBI_LIBEVENT_SRC=$(BASE_OLIBEVENT_DIR)/src
SNBI_LIBCOMMON_SRC=$(BASE_OLIBCOMMON_DIR)/src

CC = gcc

#DEBUG = -g
#OPTIM = -O3
#CFLAGS = $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Werror -Wwrite-strings -Wformat

CFLAGS = -g

LD_LIB = -lcrypt -lpthread -lrt

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


CC_SNBI_LIB_COMMON_SRCS := $(SNBI_LIBCOMMON_SRC)/olibc_common.c

CC_SNBI_LIBLIST_SRCS := $(SNBI_LIBLIST_SRC)/olibc_list.c

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
	$(SNBI_CLISIM_SRC)/an_clisim_show.c \
	$(SNBI_CLISIM_SRC)/an_clisim_debug.c \
	$(SNBI_CLISIM_SRC)/an_clisim_logg.c \
	$(SNBI_CLISIM_SRC)/an_clisim.c

CC_SNBI_LIBCLI_SRCS :=\
	$(SNBI_LIBCLI_SRC)/cparser.c \
	$(SNBI_LIBCLI_SRC)/cparser_token.c \
	$(SNBI_LIBCLI_SRC)/cparser_token_tbl.c \
	$(SNBI_LIBCLI_SRC)/cparser_token_tbl.c \
	$(SNBI_LIBCLI_SRC)/cparser_io_unix.c \
	$(SNBI_LIBCLI_SRC)/cparser_line.c \
	$(SNBI_LIBCLI_SRC)/cparser_fsm.c \
	$(SNBI_LIBCLI_SRC)/cparser_tree.c


CC_SNBI_LIBAVL_SRCS :=\
	$(SNBI_LIBAVL_SRC)/avl.c
 
CC_ALL_SRCS := $(CC_SNBI_LIBCLI_SRCS) \
	$(CC_SNBI_LIBAVL_SRCS) \
	$(CC_SNBI_LINUX_AL_SRCS) \
	$(CC_SNBI_COMMON_SRCS) \
    $(CC_SNBI_LIB_COMMON_SRCS)



all: mkdir libcli libavl an_linux_al an_common snbi_clisim

mkdir:
	echo "Making obj dir"
	echo "SNBI_LIBCLI_SRC  = $(SNBI_LIBCLI_PARSER_SRC)"
	mkdir -p $(SNBI_BIN)
	mkdir -p $(SNBI_OBJ)
	@echo ' '

libcli: $(CC_SNBI_LIBCLI_SRCS)
	echo "Building target: $@" 
	$(CC) -c $^ $(CC_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)
                
libavl: $(CC_SNBI_LIBAVL_SRCS)
	echo "Building target: $@"
	$(CC) -c $^ $(CC_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)

an_linux_al: $(CC_SNBI_LINUX_AL_SRCS)
	@echo "Building target: $@"
	$(CC) -c $^ $(CC_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)

an_common: $(CC_SNBI_COMMON_SRCS)
	@echo "Building target: $@"
	$(CC) -c $^ $(CC_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)

snbi_clisim: $(CC_SNBI_CLISIM_SRCS) $(CC_ALL_SRCS)
	@echo "Building target: $@"
	$(CC) -c $(CC_SNBI_CLISIM_SRCS) $(CC_INCDIRS) $(CFLAGS)
	mv *.o $(SNBI_OBJ)
	$(CC) -o $(SNBI_BIN)/$@ $(SNBI_OBJ)/*.o $(LD_LIB)
	@echo 'Finished building target: $@'
	@echo ' '

clean:
	@echo "Cleaning obj and bin dir"
	rm -rf $(SNBI_BIN)
	rm -rf $(SNBI_OBJ)
