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

#endif
