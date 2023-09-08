#include <bits/types/struct_timeval.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>

#include "ether.h"
#include "platform.h"

#include "util.h"
#include "net.h"
#include "dhcp.h"
#include "ip.h"
#include "sock.h"

#define DHCP_HRD_HTYPE_ETHER 0x0001

#define DHCP_FLAG_BROADCAST 0x8000

#define DHCP_SRC_PORT 68
#define DHCP_DST_PORT 67

#define DHCP_TIMEOUT 10

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define DHCP_OPT_REQ_IP    50
#define DHCP_OPT_END       255

/* DHCP MESSAGE */
#define DHCP_OPT_MSG_TYPE  53

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER    2
#define DHCP_MSG_REQUEST  3
#define DHCP_MSG_DECLINE  4
#define DHCP_MSG_ACK      5
#define DHCP_MSG_NAK      6
#define DHCP_MSG_RELEASE  7
#define DHCP_MSG_INFORM   8

/* DHCP OPTION REQUEST */
#define DHCP_OPT_PARAM_REQ 55

#define DHCP_PARAM_SUBNET     1
#define DHCP_PARAM_ROUTER     3
#define DHCP_PARAM_LEASETIME 51

#define DHCP_STATE_INIT       0
#define DHCP_STATE_SELECTING  1
#define DHCP_STATE_REQUESTING 2
#define DHCP_STATE_BOUND      3
#define DHCP_STATE_RENEWING   4
#define DHCP_STATE_REBINDING  5

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
  int soc;
  uint32_t xid;
  ip_addr_t siaddr;
  ip_addr_t ciaddr;
  ip_addr_t subnet;
  ip_addr_t router;
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
dhcp_send(struct dhcp_lease *lease)
{
  struct dhcp_hdr *hdr;
  struct sockaddr_in foreign = { .sin_family=AF_INET };
  int len;

  foreign.sin_addr = IP_ADDR_BROADCAST;
  foreign.sin_port = hton16(DHCP_DST_PORT);
  
  hdr = memory_alloc(sizeof(*hdr)); // IP_PAYLOAD_SIZE_MAX - UDP header size
  if(!hdr) {
    errorf("memory_alloc() failure");
    return -1;
  }
  len = sizeof(*hdr);

  memset(hdr, 0, sizeof(*hdr));
  hdr->op = DHCP_OP_REQUEST;
  hdr->htype = DHCP_HRD_HTYPE_ETHER;
  hdr->hlen = ETHER_ADDR_LEN;
  hdr->xid = lease->xid;
  hdr->flags = hton16(DHCP_FLAG_BROADCAST);
  memcpy(hdr->chaddr, NET_IFACE(lease->iface)->dev->addr, NET_IFACE(lease->iface)->dev->hlen);
  hdr->cookie = hton32(DHCP_MGC_CKE);
  switch(lease->state) {
  case DHCP_STATE_SELECTING:
    hdr->options[0] = DHCP_OPT_MSG_TYPE;
    hdr->options[1] = 1;
    hdr->options[2] = DHCP_MSG_DISCOVER;
    hdr->options[3] = DHCP_OPT_PARAM_REQ;
    hdr->options[4] = 3;
    hdr->options[5] = DHCP_PARAM_SUBNET;
    hdr->options[6] = DHCP_PARAM_ROUTER;
    hdr->options[7] = DHCP_PARAM_LEASETIME;
    hdr->options[8] = DHCP_OPT_END;
    debugf(YELLOW "DHCP DISCOVER" WHITE " sent");
    break;
  case DHCP_STATE_RENEWING:
    foreign.sin_addr = lease->siaddr;
    /* fall through */
  case DHCP_STATE_REQUESTING:
  case DHCP_STATE_REBINDING:
    hdr->ciaddr = lease->iface->unicast;
    hdr->secs = lease->leasetime.tv_sec;
    hdr->options[0] = DHCP_OPT_MSG_TYPE;
    hdr->options[1] = 1;
    hdr->options[2] = DHCP_MSG_REQUEST;
    hdr->options[3] = DHCP_OPT_REQ_IP;
    hdr->options[4] = IP_ADDR_LEN;
    memcpy(&hdr->options[5], &lease->ciaddr, IP_ADDR_LEN);
    hdr->options[9] = DHCP_OPT_END;
    debugf(YELLOW "DHCP REQUEST" WHITE " sent");
    break;
  }
  return sock_sendto(lease->soc, (uint8_t *)hdr, len, (struct sockaddr *)&foreign, sizeof(foreign));
}

int
dhcp_recv(struct dhcp_lease *lease) 
{
  struct dhcp_hdr *hdr;
  struct sockaddr_in foreign;
  int len, leasesec, foreignlen;
  struct timeval now;

  hdr = memory_alloc(sizeof(*hdr)); 
  if(!hdr) {
    errorf("memory_alloc() failure");
    return -1;
  }
  foreignlen = sizeof(foreign);
  len = sock_recvfrom(lease->soc, (uint8_t *)hdr, sizeof(*hdr), (struct sockaddr *)&foreign, &foreignlen);
  if(len == -1) {
    return -1;
  }
  if(hdr->cookie != hton32(DHCP_MGC_CKE)) {
    errorf("DHCP magic cookie not detected, invalid DHCP packet");
    return -1;
  }
  if(hdr->xid != lease->xid) {
    return -1;
  }
  switch(lease->state) {
  case DHCP_STATE_SELECTING:
    if(hdr->options[2] != DHCP_MSG_OFFER) {
      return -1;
    }
    debugf(YELLOW "DHCP OFFER" WHITE " received");
    lease->ciaddr = hdr->yiaddr;
    lease->siaddr = hdr->siaddr;
    // parse options
    for(int i = 0; hdr->options[i] != 0xff; i = i+(hdr->options[i+1])+2) {
      switch(hdr->options[i]) {
      case DHCP_PARAM_SUBNET:
        memcpy(&lease->subnet, &hdr->options[i+2], IP_ADDR_LEN);
        break;
      case DHCP_PARAM_ROUTER:
        memcpy(&lease->router, &hdr->options[i+2], IP_ADDR_LEN);
        break;
      case DHCP_PARAM_LEASETIME:
        gettimeofday(&now, NULL);
        memcpy(&leasesec, &hdr->options[i+2], sizeof(leasesec));
        lease->leasetime.tv_sec = hton32(leasesec);
        lease->leasebegin = now;
        break;
      }
    }
    lease->state = DHCP_STATE_REQUESTING;
    break;
  case DHCP_STATE_REQUESTING:
  case DHCP_STATE_RENEWING:
  case DHCP_STATE_REBINDING:
    switch(hdr->options[2]) {
    case DHCP_MSG_ACK:
      lease->state = DHCP_STATE_BOUND;
      debugf(YELLOW "DHCP ACK" WHITE " received");
      return 0;
    case DHCP_MSG_NAK:
      debugf("DHCP NAK received");
      return -1;
    default:
      return -1;
    }
  }
  return 0;
}



int
dhcp_begin(struct ip_iface *iface) 
{
  struct dhcp_hdr *recv;
  struct dhcp_lease *lease;
  struct sockaddr_in local = { .sin_family=AF_INET };
  struct timeval now, diff, timeout, packet_timeout;
  int len, rlen;

BEGIN:
  recv = memory_alloc(sizeof(*recv));
  lease = memory_alloc(sizeof(*lease));
  if(!recv || !lease) {
    errorf("memory_alloc() failure");
    return -1;
  }

  // open udp socket
  local.sin_addr = IP_ADDR_ANY;
  local.sin_port = hton16(DHCP_SRC_PORT);
  lease->soc = sock_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(lease->soc == -1) {
    errorf("sock_open() failure");
    return -1;
  }
  // set udp timeout
  packet_timeout.tv_sec = DHCP_TIMEOUT / 2;
  packet_timeout.tv_usec = 0;
  if(sock_setopt(lease->soc, SOL_SOCKET, SO_RCVTIMEO, (const char*)&packet_timeout, sizeof(packet_timeout)) == -1) {
    errorf("sock_setopt() failure");
    return -1;
  }
  if(sock_bind(lease->soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
    errorf("sock_bind() failure");
    return -1;
  }
  lease->next = leases;
  leases = lease;
  lease->iface = iface;
  lease->xid = random();
  lease->state = DHCP_STATE_SELECTING;
  
  gettimeofday(&timeout, NULL);
  timeout.tv_sec += DHCP_TIMEOUT;

  while(1) {
    gettimeofday(&now, NULL);
    if(timercmp(&now, &timeout, >)) {
      errorf("DHCP timeout");
      return -1;
    }
    if(dhcp_send(lease) == -1) {
      memory_free(lease);
      goto BEGIN;
    }
    if(dhcp_recv(lease) == -1) {
      continue;
    }
    if(lease->state == DHCP_STATE_BOUND) {
      sock_close(lease->soc);
      break;
    }
  }

  // update iface
  mutex_lock(&mutex);
  ip_iface_update(iface, lease->ciaddr, lease->subnet);
  char addr[IP_ADDR_STR_LEN];
  ip_addr_ntop(lease->router, addr, sizeof(addr));
  ip_route_set_default_gateway(lease->iface, addr);
  mutex_unlock(&mutex);

  return 0;
}

void 
dhcp_update(void)
{
  struct dhcp_lease *lease;
  struct timeval now, diff, timeout, packet_timeout;
  struct sockaddr_in local = { .sin_family=AF_INET };
  struct ip_iface *iface;
  char addr[IP_ADDR_STR_LEN];

  gettimeofday(&now, NULL);
  for(lease = leases; lease; lease = lease->next) {
    timersub(&now, &lease->leasebegin, &diff);
    if(diff.tv_sec > lease->leasetime.tv_sec) {
      /* lease expired */
      mutex_lock(&mutex);
      errorf("DHCP expired, addr=%s", ip_addr_ntop(lease->iface->unicast, addr, sizeof(addr)));
      ip_iface_update(lease->iface, IP_ADDR_ANY, IP_ADDR_ANY);
      leases = lease->next;
      iface = lease->iface;
      memory_free(lease);
      mutex_unlock(&mutex);
      dhcp_begin(iface);
      continue;
    }
    /* renew and rebind */
    if(diff.tv_sec > (lease->leasetime.tv_sec)*0.5) {
      lease->soc = sock_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
      if(lease->soc == -1) {
        errorf("sock_open() failure");
        continue;
      }
      gettimeofday(&now, NULL);
      timeout = now;
      timeout.tv_sec += DHCP_TIMEOUT;
      packet_timeout.tv_sec = DHCP_TIMEOUT / 2;
      packet_timeout.tv_usec = 0;
      if(sock_setopt(lease->soc, SOL_SOCKET, SO_RCVTIMEO, (const char *)&packet_timeout, sizeof(packet_timeout)) == -1) {
        errorf("sock_setopt() failure");
        continue;
      }
      local.sin_addr = lease->iface->unicast;
      local.sin_port = hton16(DHCP_SRC_PORT);
      if(sock_bind(lease->soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
        errorf("sock_bind() failure");
        continue;
      }
      /* lease renewing, dst is unicast */
      lease->state = DHCP_STATE_RENEWING;
      if(diff.tv_sec > (lease->leasetime.tv_sec)*0.5) {
        /* lease rebinding, dst is broadcast */
        lease->state = DHCP_STATE_REBINDING;
      }
      while(1) {
        gettimeofday(&now, NULL);
        if(timercmp(&now, &timeout, >)) {
          errorf("DHCP timeout");
          break;
        }
        if(dhcp_send(lease) == -1) {
          continue;
        }
        if(dhcp_recv(lease) == -1) {
          continue;
        }
        if(lease->state == DHCP_STATE_BOUND) {
          infof("DHCP UPDATE success");
          sock_close(lease->soc);
          break;
        }   
      }
    }
  }
}
