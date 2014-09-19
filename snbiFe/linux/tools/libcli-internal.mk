# /*
# * Copyright (c) 2014  Cisco Systems, All rights reserved.
# *
# * This program and the accompanying materials are made available under
# * the terms of the Eclipse License v1.0 which accompanies this distribution,
# * and is available at http://www.eclipse.org/legal/epl-v10.html
# */


BASE_DIR = ./linux/tools
BASE_LIBCLI_DIR = $(BASE_DIR)/libcli

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
