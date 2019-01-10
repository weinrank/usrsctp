#ifndef _NETMAP_DEBUG_H_
#define _NETMAP_DEBUG_H_


void netmap_pktinfo_ethernet(const char* buffer, size_t length, uint8_t recursive);
void netmap_pktinfo_arp(const char *buffer, size_t length, uint8_t recursive);
void netmap_pktinfo_ip4(const char *buffer, size_t length, uint8_t recursive);
void netmap_pktinfo_sctp(const char *buffer, size_t length, uint8_t recursive);
void netmap_pktinfo_udp(const char *buffer, size_t length, uint8_t recursive);
void netmap_pktinfo(const char *buffer, size_t length, uint8_t info, uint8_t hex_dump);


#endif // _NETMAP_DEBUG_H_
