#ifndef _USER_NETMAP_CONFIG_H_
#define _USER_NETMAP_CONFIG_H_

#ifdef NETMAP_DEBUG
#include "user_netmap_debug.h"
#endif


static const char *netmap_ifname = "ix1";

static const char *netmap_mac_src = "00:1b:21:55:1e:b9";
static const char *netmap_mac_dst = "00:1b:21:5c:64:91"; //bsd1 ix0

static const int netmap_ip_override = 0;
static const char *netmap_ip_src = "10.10.10.1";
static const char *netmap_ip_dst = "10.10.10.2";

static const int netmap_debug_operation = 1;

#if defined(NETMAP_DEBUG)
static const int netmap_debug_packet_info = 1;
static const int netmap_debug_packet_dump = 0;
#endif // defined(NETMAP_DEBUG)


#endif
