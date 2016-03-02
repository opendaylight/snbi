#ifndef __AN_EXTERNAL_ANRA_H__
#define __AN_EXTERNAL_ANRA_H__

extern void an_external_anra_register_for_events();
extern boolean an_external_anra_is_configured();
extern void an_external_anra_set_ip(an_v6addr_t reg_ip);
extern an_v6addr_t an_external_anra_get_ip();
extern void an_external_ra_init(void);

#endif //__AN_EXTERNAL_ANRA_H__
