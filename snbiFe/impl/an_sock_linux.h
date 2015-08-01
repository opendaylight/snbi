#ifndef __AN_LINUX_SOCK_H__
#define __AN_LINUX_SOCK_H__

boolean an_linux_sock_init(void);
boolean an_linux_sock_join_mld_group(an_if_t ifhndl, an_v6addr_t *group_addr);
boolean an_linux_sock_leave_mld_group(an_if_t ifhndl, an_v6addr_t *group_addr);

#endif
