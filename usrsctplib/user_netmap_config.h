#ifndef _USER_NETMAP_CONFIG_H_
#define _USER_NETMAP_CONFIG_H_

//#define NETMAP_DEBUG

#ifdef NETMAP_DEBUG
#include "netmap_debug.h"
#endif

#if defined(MULTISTACK)
static const char *netmap_ifname = "valem:usrsctp1";
static const uint16_t multistack_port = 9899;
#else //defined(MULTISTACK)
static const char *netmap_ifname = "ix0";
#endif //defined(MULTISTACK)

static const char *netmap_mac_src = "a0:36:9f:80:ea:0c";
static const char *netmap_mac_dst = "a0:36:9f:80:e9:dc"; //bsd1 ix0

static const int netmap_ip_override = 0;
static const char *netmap_ip_src = "10.9.8.101";
static const char *netmap_ip_dst = "10.9.8.104";

static const int netmap_debug_operation = 0;

#if defined(NETMAP_DEBUG)
static const int netmap_debug_packet_info = 0;
static const int netmap_debug_packet_dump = 0;
#endif // defined(NETMAP_DEBUG)


#endif
