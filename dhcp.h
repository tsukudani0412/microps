#ifndef DHCP_H
#define DHCP_H

#include <stddef.h>
#include <stdint.h>

#include "net.h"
#include "ip.h"
#include "udp.h"

#define DHCP_HDR_SIZE 228

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define DHCP_OPT_MSG_TYPE  53
#define DHCP_OPT_PARAM_REQ 55
#define DHCP_OPT_END       255

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER    2
#define DHCP_MSG_REQUEST  3
#define DHCP_MSG_DECLINE  4
#define DHCP_MSG_ACK      5
#define DHCP_MSG_NAK      6
#define DHCP_MSG_RELEASE  7
#define DHCP_MSG_INFORM   8

#define DHCP_PARAM_SUBNET 1
#define DHCP_PARAM_ROUTER 3


extern int
dhcp_init(void);
extern int
dhcp_begin(struct ip_iface *iface);

#endif
