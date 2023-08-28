#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001

/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

struct arp_hdr {
  uint16_t hrd;
  uint16_t pro;
  uint8_t hln;
  uint8_t pln;
  uint16_t op;
};

struct arp_ether_ip {
  struct arp_hdr hdr;
  uint8_t sha[ETHER_ADDR_LEN]; /* source hardware address */
  uint8_t spa[IP_ADDR_LEN];    /* source protocol address */
  uint8_t tha[ETHER_ADDR_LEN]; /* target hardware address */
  uint8_t tpa[IP_ADDR_LEN];    /* target protocol address */
};

static char *
arp_opcode_ntoa(uint16_t opcode)
{
  switch(ntoh16(opcode)) {
  case ARP_OP_REQUEST:
    return "Request";
  case ARP_OP_REPLY:
    return "Reply";
  }
  return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len) 
{
  struct arp_ether_ip *message;
  ip_addr_t spa, tpa;
  char addr[128];

  message = (struct arp_ether_ip *)data;
  flockfile(stderr);
  fprintf(stderr, CYAN "ARP packet dump\n" WHITE);
  fprintf(stderr, "   " MAZENTA "hrd" WHITE ": 0x%04x\n", ntoh16(message->hdr.hrd));
  fprintf(stderr, "   " MAZENTA "pro" WHITE ": 0x%04x\n", ntoh16(message->hdr.pro));
  fprintf(stderr, "   " MAZENTA "hln" WHITE ": %u\n", message->hdr.hln);
  fprintf(stderr, "   " MAZENTA "pln" WHITE ": %u\n", message->hdr.pln);
  fprintf(stderr, "    " MAZENTA "op" WHITE ": %u (%s)\n", 
      ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
  fprintf(stderr, "   " MAZENTA "sha" WHITE ": %s\n", 
      ether_addr_ntop(message->sha, addr, sizeof(addr)));
  memcpy(&spa, message->spa, sizeof(spa));
  fprintf(stderr, "   " MAZENTA "spa" WHITE ": %s\n", 
      ip_addr_ntop(spa, addr, sizeof(addr)));
  fprintf(stderr, "   " MAZENTA "tha" WHITE ": %s\n", 
      ether_addr_ntop(message->tha, addr, sizeof(addr)));
  memcpy(&tpa, message->tpa, sizeof(tpa));
  fprintf(stderr, "   " MAZENTA "tpa" WHITE ": %s\n", 
      ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);


}

static void 
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
  struct arp_ether_ip reply;

  reply.hdr.hrd = hton16(ARP_HRD_ETHER);
  reply.hdr.pro = hton16(ARP_PRO_IP);
  reply.hdr.hln = ETHER_ADDR_LEN;
  reply.hdr.pln = IP_ADDR_LEN;
  reply.hdr.op  = hton16(ARP_OP_REPLY);
  memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
  memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
  memcpy(reply.tha, tha, ETHER_ADDR_LEN);
  memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
  debugf("dev=" GREEN "%s" WHITE ", opcode=%s(0x%04x), len=%zu", 
      iface->dev->name, arp_opcode_ntoa(reply.hdr.op), ntoh16(reply.hdr.op), sizeof(reply));
  arp_dump((uint8_t *)&reply, sizeof(reply));
  net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void 
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
  struct arp_ether_ip *msg;
  ip_addr_t spa, tpa;
  struct net_iface *iface;

  if(len < sizeof(*msg)) {
    errorf("too short");
    return;
  }
  msg = (struct arp_ether_ip *)data;
  if(ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER) {
    errorf("unknown hardware address type, type=0x%04x", ntoh16(msg->hdr.hrd));
    return;
  }
  if(msg->hdr.hln != ETHER_ADDR_LEN) {
    errorf("invalid hardware address length, len=%zu", msg->hdr.hln);
    return;
  }
  if(ntoh16(msg->hdr.pro) != ARP_PRO_IP) {
    errorf("unknown protocol type, type=0x%04x", ntoh16(msg->hdr.pro));
    return;
  }
  if(msg->hdr.pln != IP_ADDR_LEN) {
    errorf("invalid protocol address length, len=%zu", msg->hdr.pln);
    return;
  }
  debugf("dev=" GREEN "%s" WHITE ", len=%zu", dev->name, len);
  arp_dump(data, len);
  memcpy(&spa, msg->spa, sizeof(spa));
  memcpy(&tpa, msg->tpa, sizeof(tpa));
  iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
  if(iface && ((struct ip_iface *)iface)->unicast == tpa) {
    if(ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
      arp_reply(iface, msg->sha, spa, msg->sha);
    }
  }
}

int
arp_init(void)
{
  if(net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
    errorf("net_protocol_register() failure");
    return -1;
  }
  return 0;
}
