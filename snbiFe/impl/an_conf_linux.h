#ifndef __AN_CONF_LINUX_H__
#define __AN_CONF_LINUX_H__

#include <olibc_common.h>

extern boolean
an_system_init_linux(void);

extern boolean
an_enable_cmd_handler(void);

extern boolean
an_disable_cmd_handler(void);

extern boolean
an_config_udi_cmd_handler(char *udi);

extern boolean
an_config_intf_enable_cmd_handler(int ifindex);

extern boolean
an_config_intf_disable_cmd_handler(int ifindex);

extern boolean
an_config_register_ip_cmd_handler(char *ip_str);

extern boolean
an_config_global_quit_cmd_handler (void);

extern boolean
an_config_global_cleanup_cmd_handler (void);
#endif
