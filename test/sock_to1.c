#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

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
  if(net_init() == -1) {
    errorf("net_init() failure");
    return -1;
  }
  dev = loopback_init();
  if(!dev) {
    errorf("loopback_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
  if(!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if(ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  }
 
  //ethernet
  dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
  if(!dev) {
    errorf("ether_tap_init() failure");
    return -1;
  }
  iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
  if(!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if(ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  } 
  if(ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
    errorf("ip_route_set_default_gateway() failure");
    return -1;
  }
  if(net_run() == -1) {
    errorf("net_run() failure");
    return -1;
  }
return 0;
}


static int
cleanup(void)
{
  sleep(1);
  net_shutdown();
  return 0;
}

int
main(int atgc, char *argv[])
{
  struct sockaddr_in local = { .sin_family=AF_INET };
  struct ip_endpoint foreign;
  struct timeval timeout;
  int soc, foreignlen;
  uint8_t buf[2048];
  ssize_t ret;

  if(setup() == -1) {
    errorf("setup() failure");
    return -1;
  }

  local.sin_port = hton16(7);
  soc = sock_open(AF_INET, SOCK_DGRAM, IPPROTO_TCP);

  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  errorf("%d", sock_setopt(soc, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)));
 
  if(sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
    errorf("sock_bind() failure");
    return -1;
  }

  if(soc == -1) {
    errorf("sock_open() failure");
    return -1;
  }
  while(!terminate) {
    ret = sock_recvfrom(soc, buf, sizeof(buf), (struct sockaddr *)&foreign, &foreignlen);
    if(ret == -1) {
      if(errno == EINTR) {
        continue;
      } else {
        return -1;
      }
    }
    hexdump(stderr, buf, ret);
  }
  sock_close(soc);
  cleanup();
  return 0;
}

