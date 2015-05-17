/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __AN_FILE_LINUX_H__
#define __AN_FILE_LINUX_H__


#include <an_file.h>
#include <an_types.h>

uint32_t ifs_fd_get_size(int fd);
uint32_t ifs_write_until(int fd, void *vbuffer, uint32_t nbytes);

#endif
