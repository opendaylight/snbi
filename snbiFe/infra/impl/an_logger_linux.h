/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this
 * distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifndef __AN_LOGGER_LINUX_H__
#define __AN_LOGGER_LINUX_H__
#include <an_logger.h>
#include <an_file.h>


boolean an_log_fd_set(an_file_descr_t fd);
boolean an_log_stdout_set(void);
boolean an_log_file_set(uint8_t *file_name);

#endif
