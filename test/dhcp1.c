#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "dhcp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

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
  iface = ip_iface_alloc("0.0.0.0", "0.0.0.0");
  if(!iface) {
    errorf("ip_iface_alloc() failure");
    return -1;
  }
  if(ip_iface_register(dev, iface) == -1) {
    errorf("ip_iface_register() failure");
    return -1;
  } 
  if(net_run() == -1) {
    errorf("net_run() failure");
    return -1;
  }
  if(dhcp_begin(iface) == -1) {
    errorf("dhcp_begin() failure");
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
  int count = 0;

  setup();
  while(!terminate) {
    count++;
    if(count > 30) {
      dhcp_update();
      count = 0;
    }
    sleep(1);
  }
  cleanup();
  return 0;
}

