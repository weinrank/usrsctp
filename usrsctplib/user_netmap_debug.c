
#include <stdio.h>
#ifdef NETMAP_DEBUG
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/ethernet.h>

#include <sys/mman.h>
#include <user_mbuf.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <user_netmap.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <netinet/udp.h>
#include <netinet/sctp_input.h>

#include "user_netmap_debug.h"

#pragma pack(push,1) // disable padding
struct arp_packet {
	uint16_t 	hardware_type;
	uint16_t 	protocol_type;
	uint8_t 	hardware_size;
	uint8_t 	protocol_size;
	uint16_t 	operation;
	uint8_t 	src_mac[6];
	uint32_t 	src_ip;
	uint8_t 	dst_mac[6];
	uint32_t 	dst_ip;
};
#pragma pack(pop)

void netmap_pktinfo(const char *buffer, size_t length, uint8_t info, uint8_t hex_dump) {

    if(info) {
        netmap_pktinfo_ethernet(buffer,length,1);
    }

    if(hex_dump) {

    }
}

void netmap_pktinfo_ethernet(const char* buffer, size_t length, uint8_t recursive) {
	struct ether_header *eth_header;

	if (length < sizeof(struct ether_header)) {
        printf("error: packetsize < ethernet header!\n");
        return;
    }

    eth_header = (struct ether_header*)buffer;
    SCTP_PRINTF("\t## MAC");
    SCTP_PRINTF("\t%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    SCTP_PRINTF(" -> ");
    SCTP_PRINTF("%s\n", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    if(recursive) {
	    switch(htons(eth_header->ether_type)) {

	    	/* IP */
	    	case ETHERTYPE_IP:
			    netmap_pktinfo_ip4(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header),recursive);
			    break;

			/* ARP */
			case ETHERTYPE_ARP:
				netmap_pktinfo_arp(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header),recursive);
				break;

			default:
				SCTP_PRINTF("ethernet - unknown ether_type - discarding\n");
				break;
		}
	}
}

// print arp info
void netmap_pktinfo_arp(const char *buffer, size_t length, uint8_t recursive) {
	struct arp_packet *arp_packet;

	if (length < sizeof(struct arp_packet)) {
		SCTP_PRINTF("error: packetsize < arp packet\n");
		return;
	}

	arp_packet = (struct arp_packet*)buffer;
	SCTP_PRINTF("\t## ARP");

	switch(arp_packet->operation) {

		// request
		case htons(1):
			SCTP_PRINTF("\tREQUEST - ");
			SCTP_PRINTF(" %s", inet_ntoa(*(struct in_addr*)&arp_packet->src_ip));
			SCTP_PRINTF(" requests");
			SCTP_PRINTF(" %s\n", inet_ntoa(*(struct in_addr*)&arp_packet->dst_ip));
			break;

		// response
		case htons(2):
			SCTP_PRINTF("\tRESPONSE - ");
			SCTP_PRINTF(" %s", inet_ntoa(*(struct in_addr*)&arp_packet->src_ip));
			SCTP_PRINTF(" responses");
			SCTP_PRINTF(" %s\n", inet_ntoa(*(struct in_addr*)&arp_packet->dst_ip));
			break;
	}
}

// print ipv4 info
void netmap_pktinfo_ip4(const char *buffer, size_t length, uint8_t recursive) {
	struct ip *ip_header;
	uint16_t ip_header_len;

	if(length < sizeof(struct ip)) {
		SCTP_PRINTF("error: packetsize < ip packet\n");
		return;
	}
	ip_header = (struct ip*)buffer;
    ip_header_len = ((ip_header->ip_hl & 0xf) * 4);

    SCTP_PRINTF("\t## IP4");
    SCTP_PRINTF("\t%s", inet_ntoa(ip_header->ip_src));
    SCTP_PRINTF(" -> ");
    SCTP_PRINTF("%s\n", inet_ntoa(ip_header->ip_dst));

    if(recursive) {
	    switch (ip_header->ip_p) {
		    case IPPROTO_SCTP:
		        netmap_pktinfo_sctp(buffer + ip_header_len, length - ip_header_len, recursive);
		        break;
		    case IPPROTO_UDP:
		        netmap_pktinfo_udp(buffer + ip_header_len, length - ip_header_len, recursive);
		        break;
            case IPPROTO_TCP:
                printf("\tTCP - ignoring\n");
		    default:
		        printf("\tunknown protocol: %u\n",ip_header->ip_p);
	    }
	}
}

// print sctp info
void netmap_pktinfo_sctp(const char *buffer, size_t length, uint8_t recursive) {
	struct sctphdr *sctp_header;

	if (length < sizeof(struct sctphdr)) {
		SCTP_PRINTF("error: packetsize < sctp header\n");
		return;
	}
	sctp_header = (struct sctphdr*)buffer;
	SCTP_PRINTF("\t## SCTP\n");
}

// print udp info
void netmap_pktinfo_udp(const char *buffer, size_t length, uint8_t recursive) {
	struct udphdr *udp_header;

	if (length < sizeof(struct udphdr)) {
		SCTP_PRINTF("error: packetsize < udp header\n");
		return;
	}
	udp_header = (struct udphdr*)buffer;

	SCTP_PRINTF("\t## UDP");
    SCTP_PRINTF("\t:%u", ntohs(udp_header->uh_sport));
    SCTP_PRINTF(" -> ");
    SCTP_PRINTF(":%u\n", ntohs(udp_header->uh_dport));
    //SCTP_PRINTF(" - length %u\n", ntohs(udp_header->uh_ulen));
}
#endif // #ifdef NETMAP_DEBUG
