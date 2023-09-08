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

#define DHCP_REQUEST_TIMEOUT 10

#define DHCP_STATE_INIT       0
#define DHCP_STATE_SELECTING  1
#define DHCP_STATE_REQUESTING 2
#define DHCP_STATE_RENEWING   3
#define DHCP_STATE_REBINDING  4

#define DHCP_MAGIC_COOKIE 0x63825363


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
  uint32_t cookie;
  uint8_t options[60]; /* 64 - MAGIC COOKIE(4) bytes */
};

struct dhcp_lease {
  struct dhcp_lease *next;
  int state;
  uint32_t xid;
  struct ip_iface *iface;
  struct timeval leasetime;
  struct timeval leasebegin;
};

static uint32_t DHCP_MGC_CKE = DHCP_MAGIC_COOKIE;

static mutex_t mutex = MUTEX_INITIALIZER;
static struct dhcp_lease *leases;

void
dhcp_dump(const uint8_t *data, size_t len) 
{
  struct dhcp_hdr *hdr;
  char addr[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];
  char addr3[IP_ADDR_STR_LEN];
  char addr4[IP_ADDR_STR_LEN];

  flockfile(stderr);
  hdr = (struct dhcp_hdr *)data;
  fprintf(stderr, CYAN "DHCP header dump\n" WHITE);
  fprintf(stderr, "      " MAZENTA "op" WHITE ": 0x%x\n", hdr->op);
  fprintf(stderr, "   " MAZENTA "htype" WHITE ": 0x%x\n", hdr->htype);
  fprintf(stderr, "    " MAZENTA "hlen" WHITE ": %u\n", hdr->hlen);
  fprintf(stderr, "    " MAZENTA "hops" WHITE ": %u\n", hdr->hops);
  fprintf(stderr, "     " MAZENTA "xid" WHITE ": 0x%04x\n", ntoh32(hdr->xid));
  fprintf(stderr, "    " MAZENTA "secs" WHITE ": %u\n", ntoh16(hdr->secs));
  fprintf(stderr, "   " MAZENTA "flags" WHITE ": 0x%02x (%016b)\n", ntoh16(hdr->flags), ntoh16(hdr->flags));
  fprintf(stderr, "  " MAZENTA "ciaddr" RED   ": %s\n" WHITE, 
      ip_addr_ntop(hdr->ciaddr, addr, sizeof(addr)));
  fprintf(stderr, "  " MAZENTA "yiaddr" RED   ": %s\n" WHITE, 
      ip_addr_ntop(hdr->yiaddr, addr, sizeof(addr)));
  fprintf(stderr, "  " MAZENTA "siaddr" RED   ": %s\n" WHITE, 
      ip_addr_ntop(hdr->siaddr, addr, sizeof(addr)));
  fprintf(stderr, "  " MAZENTA "giaddr" RED   ": %s\n" WHITE, 
      ip_addr_ntop(hdr->giaddr, addr, sizeof(addr)));
  funlockfile(stderr);
}

int
dhcp_begin(struct ip_iface *iface) 
{
  struct dhcp_hdr *hdr, *recv;
  struct dhcp_lease *lease;
  struct ip_endpoint local, foreign;
  int len, rlen;

  hdr = memory_alloc(sizeof(*hdr)); // IP_PAYLOAD_SIZE_MAX - UDP header size
  recv = memory_alloc(sizeof(*recv));
  lease = memory_alloc(sizeof(*lease));
  if(!hdr || !lease) {
    errorf("memory_alloc() failure");
    return -1;
  }

  len = sizeof(*hdr);

  memset(hdr, 0, sizeof(*hdr));
  hdr->op = DHCP_OP_REQUEST;
  hdr->htype = DHCP_HRD_HTYPE_ETHER;
  hdr->hlen = ETHER_ADDR_LEN;
  //hdr->xid = random();
  hdr->xid = hton32(0x3903f326);
  hdr->flags = hton16(DHCP_FLAG_BROADCAST);
  memcpy(hdr->chaddr, NET_IFACE(iface)->dev->addr, NET_IFACE(iface)->dev->hlen);
  hdr->cookie = hton32(DHCP_MGC_CKE);
  hdr->options[0] = DHCP_OPT_MSG_TYPE;
  hdr->options[1] = 1;
  hdr->options[2] = DHCP_MSG_DISCOVER;
  hdr->options[3] = DHCP_OPT_PARAM_REQ;
  hdr->options[4] = 2;
  hdr->options[5] = DHCP_PARAM_SUBNET;
  hdr->options[6] = DHCP_PARAM_ROUTER;
  hdr->options[7] = DHCP_OPT_END;

  lease->next = leases;
  leases = lease;
  lease->state = DHCP_STATE_SELECTING;
  lease->xid = hdr->xid;
  lease->iface = iface;

  ip_endpoint_pton("0.0.0.0:68", &local);
  ip_endpoint_pton("255.255.255.255:67", &foreign);
  int soc = udp_open();
  if(soc == -1) {
    errorf("udp_open() failure");
    return -1;
  }
  if(udp_bind(soc, &local) == -1) {
    errorf("udp_bind() failure");
    return -1;
  }
  udp_sendto(soc, (uint8_t *)hdr, len, &foreign);
  debugf(YELLOW "DHCP DISCOVER" WHITE " sent");

  // receive DHCP OFFER
  rlen = udp_recvfrom(soc, (uint8_t *)recv, sizeof(*recv), NULL);
  if(rlen == -1) {
    return -1;
  }
  if(recv->cookie != hton32(DHCP_MGC_CKE)) {
    errorf("DHCP magic cookie not detected, invalid DHCP packet");
    return -1;
  }
  if(recv->options[2] != DHCP_MSG_OFFER) {
    errorf("DHCP OFFER does not received");
    return -1;
  }
  debugf(YELLOW "DHCP OFFER" WHITE " received");
  lease->state = DHCP_STATE_REQUESTING;

  // send DHCP REQUEST
  hdr->ciaddr = lease->iface->unicast;
  hdr->secs = recv->secs;
  local.addr = lease->iface->unicast;
  hdr->options[2] = DHCP_MSG_REQUEST;
  hdr->options[3] = DHCP_OPT_END;
  memset(&hdr->options[4], 0, 56);
  udp_sendto(soc, (uint8_t *)hdr, len, &foreign);
  debugf(YELLOW "DHCP REQUEST" WHITE " sent");

  // DHCP ACK receive
  rlen = udp_recvfrom(soc, (uint8_t *)recv, sizeof(*recv), NULL);
  if(rlen == -1) {
    return -1;
  }
  if(recv->cookie != hton32(DHCP_MGC_CKE)) {
    errorf("DHCP magic cookie not detected, invalid DHCP packet");
    return -1;
  }
  if(recv->options[2] != DHCP_MSG_ACK) {
    errorf("DHCP ACK does not received");
    return -1;
  }
  infof(YELLOW "DHCP ACK" WHITE " received, DHCP configulation success");
 
  // update iface
  mutex_lock(&mutex);
  ip_iface_update(iface, recv->yiaddr, recv->options[5]);
  mutex_unlock(&mutex);

  return 0;  
}

int 
dhcp_send(struct dhcp_lease *lease, int type)
{
  return 0;
}


int 
dhcp_init() {
  return 0;
}
