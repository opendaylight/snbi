/*
 * Copyright (c) 2014  Cisco Systems, All rights reserved.
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef __AN_PROC_LINUX_H__
#define __AN_PROC_LINUX_H__

#include <an_if.h>
#include <an_sudi.h>
#include <an_cert.h>
#include <an_timer.h>
#include <an_logger.h>
#include <an_pak.h>
#include <an_mem.h>
#include <an_tunnel.h>
#include <an_ntp.h>
#include <an_misc.h>
#include <an_file.h>
#include <an_str.h>
#include <an_types.h>
#include <an_bs.h>
#include <an_nd.h>
#include <an_event_mgr.h>
#include <an_if_mgr.h>
#include <an_acp.h>
#include <an.h>
#include <olibc_msg_q.h>

extern olibc_pthread_hdl an_pthread_hdl;
extern olibc_msg_q_hdl an_pmsg_q_hdl;

extern an_watched_boolean *an_wb_node_discovered;
extern an_watched_boolean *an_setup_done_by_user;
extern an_watched_boolean *an_manual_config_detected;
void an_process_send_message (an_thread_t pid, const char *key, ulong message_num, void *pointer, ulong message_arg);

void an_proc_init(void);
void an_proc_uninit(void);

void an_process_call(void );
void an_process_call_shut(void);
void an_process_call_no_registrar(uint32_t value_chk);

#endif

