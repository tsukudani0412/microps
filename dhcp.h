#ifndef DHCP_H
#define DHCP_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"
#include "ip.h"
#include "udp.h"


extern int
dhcp_begin(struct ip_iface *iface);
extern void
dhcp_update(void);

#endif
