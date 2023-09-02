#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

#include "colors.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint32_t values;
};

struct icmp_echo {
  uint8_t type;
  uint8_t code;
  uint16_t sum;
  uint16_t id;
  uint16_t seq;
};

static char *
icmp_type_ntoa(uint8_t type) {
  switch (type) {
  case ICMP_TYPE_ECHOREPLY:
    return "EchoReply";
  case ICMP_TYPE_DEST_UNREACH:
    return "DestinationUnreachable";
  case ICMP_TYPE_SOURCE_QUENCH:
    return "SourceQuench";
  case ICMP_TYPE_REDIRECT:
    return "Redirect";
  case ICMP_TYPE_ECHO:
    return "Echo";
  case ICMP_TYPE_TIME_EXCEEDED:
    return "TimeExceeded";
  case ICMP_TYPE_PARAM_PROBLEM:
    return "ParameterProblem";
  case ICMP_TYPE_TIMESTAMP:
    return "Timestamp";
  case ICMP_TYPE_TIMESTAMPREPLY:
   return "TimestampReply";
  case ICMP_TYPE_INFO_REQUEST:
    return "InformationRequest";
  case ICMP_TYPE_INFO_REPLY:
    return "InformationReply";
  }
  return "Unknown";
}

static void 
icmp_dump(const uint8_t *data, size_t len)
{
  struct icmp_hdr *hdr;
  struct icmp_echo *echo;

  flockfile(stderr);
  hdr = (struct icmp_hdr *)data;
  fprintf(stderr, CYAN "ICMP header dump\n" WHITE);
  fprintf(stderr, "    " MAZENTA "type" WHITE ": %u (" CYAN "%s" WHITE ")\n", hdr->type, icmp_type_ntoa(hdr->type));
  fprintf(stderr, "    " MAZENTA "code" WHITE ": %u\n",      hdr->code);
  fprintf(stderr, "     " MAZENTA "sum" WHITE ": 0x%04x\n",  ntoh16(hdr->sum));

  switch(hdr->type) {
  case ICMP_TYPE_ECHOREPLY:
  case ICMP_TYPE_ECHO:
    echo = (struct icmp_echo *)hdr;
    fprintf(stderr, "      " MAZENTA "id" WHITE ": %u\n", ntoh16(echo->id));
    fprintf(stderr, "     " MAZENTA "seq" WHITE ": %u\n", ntoh16(echo->seq));
    break;
  default:
    fprintf(stderr, "  " MAZENTA "values" WHITE ": 0x%08x\n", ntoh32(hdr->values));
    break;
  }
#ifdef HEXDUMP
  hexdump(stderr, data, len);
#endif
  funlockfile(stderr);
}

void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
  struct icmp_hdr *hdr;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  hdr = (struct icmp_hdr *)data;

  if(len < sizeof(*hdr)) {
    errorf("too short size=%u", len);
    return;
  }
  if(cksum16((uint16_t *)data, len, 0) != 0) {
    errorf("invalid icmp checksum, sum=0x%04x, verify=0x%04x", hdr->sum, cksum16((uint16_t *)data, len, 0));
    //icmp_dump(data, len);
    return;
  }

  debugf(RED "%s" WHITE " => " RED "%s" WHITE ", len=%zu",
      ip_addr_ntop(src, addr1, sizeof(addr1)), 
      ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
  //icmp_dump(data, len);
  switch(hdr->type) {
  case ICMP_TYPE_ECHO:
    /* Responds with the address of the received interface. */
    if(dst != iface->unicast) {
      dst = iface->unicast;
    }
    icmp_output(ICMP_TYPE_ECHOREPLY, hdr->code, hdr->values, (uint8_t *)(hdr + 1), len - sizeof(*hdr), dst, src);
    break;
  default:
    break;
  }
}

int
icmp_output(uint8_t type, uint8_t code, uint32_t value, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
  uint8_t buf[ICMP_BUFSIZ];
  struct icmp_hdr *hdr;
  size_t msg_len;
  char addr1[IP_ADDR_STR_LEN];
  char addr2[IP_ADDR_STR_LEN];

  hdr = (struct icmp_hdr *)buf;
  msg_len = sizeof(*hdr) + len;
  hdr->type = type;
  hdr->code = code;
  hdr->sum = 0;
  hdr->values = value;
  memcpy(hdr + 1, data, len);
  hdr->sum = cksum16((uint16_t *)hdr, msg_len, 0);

  debugf(RED "%s" WHITE " => " RED "%s" WHITE ", len=%zu", 
      ip_addr_ntop(src, addr1, sizeof(addr1)),
      ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
  //icmp_dump((uint8_t *)hdr, msg_len);
  
  return ip_output(IP_PROTOCOL_ICMP, (uint8_t *)hdr, msg_len, src, dst);
}

int icmp_init(void)
{
  if(ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
    errorf("ip_protocol_register() failure, type=%u", IP_PROTOCOL_ICMP);
    return -1;
  }
  return 0;
}
