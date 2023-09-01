#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "ether.h"
#include "platform.h"

#include "util.h"
#include "net.h"
#include "arp.h"
#include "dhcp.h"
#include "ip.h"
#include "udp.h"

#define DHCP_HRD_HTYPE_ETHER 0x0001

#define DHCP_FLAG_BROADCAST 0x8000

#define DHCP_SRC_PORT 68
#define DHCP_DST_PORT 67

#define DHCP_STATE_

struct dhcp_hdr {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops; /* count relay hops */
  uint32_t xid; /* transaction id */
  uint16_t secs; /* lease remain time (secs) */
  uint16_t flags; 
  ip_addr_t ciaddr; /* client ip addr */
  ip_addr_t yiaddr; /* your ip addr (leased addr from server) */
  ip_addr_t siaddr; /* tftp server addr */
  ip_addr_t giaddr; /* dhcp relay gateway addr */
  uint8_t chaddr[16]; /* client hardware addr */
  uint8_t sname[64];  /* server name */
  uint8_t file[128];  /* tftp file path */
  uint8_t options[];
};

struct dhcp_lease {
  int state;
  uint32_t xid;
  struct net_iface *iface;
  struct timeval leasetime;
  struct timeval leasebegin;
};

int dhcp_begin(struct ip_iface *iface) 
{
  struct dhcp_hdr *hdr;
  struct ip_endpoint local, foreign;

  hdr = memory_alloc(sizeof(*hdr));
  if(!hdr) {
    errorf("memory_alloc() failure");
    return -1;
  }
  memset(hdr, 0, sizeof(*hdr));
  hdr->op = DHCP_OP_REQUEST;
  hdr->htype = DHCP_HRD_HTYPE_ETHER;
  hdr->hlen = ETHER_ADDR_LEN;
  hdr->xid = random();
  hdr->flags = DHCP_FLAG_BROADCAST;
  //memcpy(hdr->chaddr, NET_IFACE(iface)->dev->addr, NET_IFACE(iface)->dev->alen);

  ip_endpoint_pton("0.0.0.0:67", &local);
  ip_endpoint_pton("255.255.255.255:68", &foreign);
  int soc = udp_open();
  if(soc == -1) {
    errorf("udp_open() failure");
    return -1;
  }
  if(udp_bind(soc, &local) == -1) {
    errorf("udp_bind() failure");
    return -1;
  }
  udp_sendto(soc, (uint8_t *)hdr, sizeof(*hdr), &foreign);
}

  
