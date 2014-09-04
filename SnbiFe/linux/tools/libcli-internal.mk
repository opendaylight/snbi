#
#  Vijay Anand R.
#  
#  Copyright (c) 2014 by cisco Systems, Inc.
#  All rights reserved.
#

BASE_DIR = /vob/ss.comp1/autonomic-networking/src/linux/tools
BASE_LIBCLI_DIR = $(BASE_DIR)/libcli-internal

CC_INCDIRS :=\
	-I$(BASE_LIBCLI_DIR)/src \
	-I$(BASE_LIBCLI_DIR)/include
       
OBJ=$(BASE_LIBCLI_DIR)/obj
SRC=$(BASE_LIBCLI_DIR)/src

CC = gcc

DEBUG = -g
OPTIM = -O3
CFLAGS = $(DEBUG) 

LD_FLAGS = -shared

LD_LIB = -lcrypt

CC_LIBCLI_OBJS :=\
	$(OBJ)/libcli.o

CC_LIBCLI_SRCS :=\
	$(SRC)/libcli.c \
	$(SRC)/automore.c \
	$(SRC)/flread.c \
	$(SRC)/getopts.c \
	$(SRC)/strie.c \
	$(SRC)/termio.c

all: mkdir libcli.o

mkdir:
	@echo "Making obj dir"
	mkdir -p $(OBJ)
	@echo ' '

libcli.o: $(CC_LIBCLI_SRCS)
	@echo "Building target: $@"
	$(CC) -o $(OBJ)/$@ $^ $(CC_INCDIRS) $(CFLAGS) \
		$(LD_LIB) $(LD_FLAGS) -fPIC
	@echo 'Finished building target: $@'
	@echo ' '


clean:
	@echo "Cleaning obj and bin dir"
	rm -rf $(OBJ)
