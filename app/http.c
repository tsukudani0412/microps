#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
  (void)s;
  terminate = 1;
  net_raise_event();
}

  static int
setup(void)
{
  struct net_device *dev;
  struct ip_iface *iface;

  signal(SIGINT, on_signal);
  if (net_init() == -1) {
    errorf("net_init() failure");
    return -1;
  }
  dev = loopback_init();
  if (!dev) {
    errorf("loopback_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
  if (!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  }
  dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
  if (!dev) {
    errorf("ether_tap_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
  if (!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if (ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  }
  if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
    errorf("ip_route_set_default_gateway() failure");
    return -1;
  }
  if (net_run() == -1) {
    errorf("net_run() failure");
    return -1;
  }
  return 0;
}

  int
main(int argc, char *argv[])
{
  struct ip_endpoint local;
  int soc, port;
  FILE *fp;
  uint8_t inbuf[2048];
  char buf[2048];

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf),
      "HTTP/1.0 200 OK\r\n"
      "Content-Length: 78\r\n"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<h1>200 OK</h1>\r\n"
      "<h2>Hello, world!</h2>\r\n"
      "<i>microhttpsrv works on microps!</i>");
  char err404[] = {
      "HTTP/1.0 404 Not Found\r\n"
      "Content-Length: 124\r\n"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<h1>404 Not Found</h1>\r\n"
      "<h2>The requested document was not found on this server.</h2>\r\n"
      "<i>microhttpsrv works on microps!</i>"};

  char not_support501[] = {
      "HTTP/1.0 501 Not Implemented\r\n"
      "Content-Length: 133\r\n"
      "Content-Type: text/html\r\n"
      "\r\n"
      "<h1>501 Not Implemented</h1>\r\n"
      "<h2>The requested method is not implemented by this server.</h2>\r\n"
      "<i>microhttpsrv works on microps!</i>"};

  /*
   * Parse command line parameters
   */
  switch (argc) {
    case 3:
      if (ip_addr_pton(argv[argc-2], &local.addr) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", optarg);
        return -1;
      }
      /* fall through */
    case 2:
      port = strtol(argv[argc-1], NULL, 10);
      if (port < 0 || port > UINT16_MAX) {
        errorf("invalid port, port=%s", optarg);
        return -1;
      }
      local.port = hton16(port);
      break;
    default:
      fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
      return -1;
  }
  /*
   * Setup protocol stack
   */
  if (setup() == -1) {
    errorf("setup() failure");
    return -1;
  }
  /*
   *  Application Code
   */
  while (!terminate) {
    int recvsize = 0;
    soc = tcp_open_rfc793(&local, NULL, 0);
    if (soc == -1) {
      errorf("tcp_open_rfc793() failure");
      return -1;
    }
    recvsize = tcp_receive(soc, inbuf, sizeof(inbuf));
    hexdump(stderr, inbuf, recvsize);
    printf("%s", inbuf);
    
    //parse request
    if(strcmp(strtok((char *)&inbuf, " "), "GET") == 0) {
      char *path;
      path = strtok(NULL, " ");
      printf("==============================================================================================================\n");
      printf("%s\n==============================================================================================================\n", path);
      if(strcmp(path, "/") != 0) {
        tcp_send(soc, (uint8_t *)err404, sizeof(err404));
        tcp_close(soc);
        continue;
      }
      tcp_send(soc, (uint8_t *)buf, sizeof(buf));
      tcp_close(soc);
    } else {
      tcp_send(soc, (uint8_t *)not_support501, sizeof(not_support501));
      tcp_close(soc);
    }
  }
  /*
   * Cleanup protocol stack
   */
  net_shutdown();
  return 0;
}
