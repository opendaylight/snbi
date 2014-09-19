#
# Copyright (c) 2014  Cisco Systems, All rights reserved.
# 
# This program and the accompanying materials are made available under
# the terms of the Eclipse License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
#


BASE_DIR = ./linux/tools
BASE_LIBAVL_DIR = $(BASE_DIR)/libavl

CC_LIBAVL_SRCS=$(SRC_DIR)/libavl.c

OBJ=$(BASE_LIBAVL_DIR)/obj
SRC=$(BASE_LIBAVL_DIR)/src

CC = gcc
DEBUG = -g
OPTIM = -O3
CFLAGS = $(DEBUG) $(OPTIM) -Wall -std=c99 -pedantic -Wformat-security -Wno-format-zero-length -Werror -Wwrite-strings -Wformat -Wextra -Wsign-compare -Wcast-align -Wno-unused-parameter 

LD_FLAGS = -shared

CC_LIBAVL_OBJS :=\
	$(OBJ)/libavl.o

CC_LIBAVL_SRCS :=\
	$(SRC)/avl.c

SRC_DIR = $(BASE_LIBAVL_DIR)/src/.

CC_INCDIRS := -I$(BASE_LIBAVL_DIR)/include

default: mkdir libavl.o

mkdir:
	@echo "Making obj dir for libavl"
	mkdir -p $(OBJ)
	@echo ' '

libavl.so: $(CC_LIBAVL_SRCS)
	$(CC) -c -shared $(SRC_DIR)/avl.c $(CC_INCDIRS) -o $(OBJ)/libavl.so

libavl.o: $(CC_LIBAVL_SRCS)
	 @echo "Building target: $@"
	 $(CC) -o $(OBJ)/$@ $^ $(CC_INCDIRS) $(CFLAGS) \
	 $(LD_LIB) $(LD_FLAGS) -fPIC
	 @echo 'Finished building target: $@'
	 @echo ' '

clean: 
	@echo "Clean libavl obj and bin dir"
	 rm -rf $(OBJ)

