
#include <stdio.h>

#if defined(NETMAP) || defined(MULTISTACK)
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

/* ########## CONFIG SECTION ########## */

#if defined(MULTISTACK)
const char *netmap_ifname = "valem:usrsctp1";
const uint16_t multistack_port = 9899;
#else
const char *netmap_ifname = "igb1";
#endif

const char *netmap_mac_src = "00:1b:21:73:a2:e9";
const char *netmap_mac_dst = "00:1b:21:75:dc:7d";

const int netmap_ip_override = 0;
const char *netmap_ip_src = "10.0.1.201";
const char *netmap_ip_dst = "10.0.1.202";

const int netmap_debug_pkts = 0; // print information about ever incoming or outgoing packet
const int netmap_debug_operation = 0; // print operation information
const int netmap_debug_hexdump = 0; // hexdump ever packet

#define MAXLEN_MBUF_CHAIN 32

/* ########## CONFIG SECTION END ########## */

static void 	usrsctp_netmap_hexdump(char *desc, void *addr, int len);
static uint16_t usrsctp_netmap_ip_wrapsum(u_int32_t sum);
static uint16_t usrsctp_netmap_ip_checksum(const void *data, uint16_t len, uint32_t sum);
static void 	usrsctp_netmap_pkt_info_ethernet(char* buffer, uint32_t length, uint8_t recursive);
static void 	usrsctp_netmap_pkt_info_ipv4(char *buffer, uint32_t length, uint8_t recursive);
static void 	usrsctp_netmap_pkt_info_arp(char *buffer, uint32_t length, uint8_t recursive);
static void 	usrsctp_netmap_pkt_info_sctp(char *buffer, uint32_t length, uint8_t recursive);
static void 	usrsctp_netmap_pkt_info_udp(char *buffer, uint32_t length, uint8_t recursive);
static void 	usrsctp_netmap_handle_ethernet(char* buffer, uint32_t length);
static void 	usrsctp_netmap_handle_ipv4(char *buffer, uint32_t length);
static void 	usrsctp_netmap_handle_sctp(char *buffer, uint32_t length, struct ip *ip_header, uint16_t udp_encaps_port);
static void 	usrsctp_netmap_handle_udp(char *buffer, uint32_t length, struct ip *ip_header);
static void 	usrsctp_netmap_handle_arp(char *buffer, uint32_t length);


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
} __attribute__((__packed__));

// dump packet for wireshark etc
// stolen from http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
static void usrsctp_netmap_hexdump (char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf ("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf ("  %s\n", buff);
}

// for ip checksum
// stolen from pkt-gen.c
static uint16_t usrsctp_netmap_ip_wrapsum(u_int32_t sum) {
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

// compute the checksum of the given ip header.
// stolen from netmap pkt-gen.c
static uint16_t usrsctp_netmap_ip_checksum(const void *data, uint16_t len, uint32_t sum) {
	const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}

/* ########## PACKET INFO SECTION ########## */

// print information about ethernet packet
static void usrsctp_netmap_pkt_info_ethernet(char* buffer, uint32_t length, uint8_t recursive) {
	struct ether_header *eth_header;

	SCTP_PRINTF("netmap packet info - length: %u\n",length);
	if (length < sizeof(struct ether_header)) {
        SCTP_PRINTF("error: packet too short for ethernet header!\n");
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
			    usrsctp_netmap_pkt_info_ipv4(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header),recursive);
			    break;

			/* ARP */
			case ETHERTYPE_ARP:
				usrsctp_netmap_pkt_info_arp(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header),recursive);
				break;

			default:
				SCTP_PRINTF("ethernet - uknown ether_type\n");
				break;
		}
	}
}

// print arp info
static void usrsctp_netmap_pkt_info_arp(char *buffer, uint32_t length, uint8_t recursive) {
	struct arp_packet *arp_packet;

	if (length < sizeof(struct arp_packet)) {
		SCTP_PRINTF("error: packet too short for arp packet!\n");
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
static void usrsctp_netmap_pkt_info_ipv4(char *buffer, uint32_t length, uint8_t recursive) {
	struct ip *ip_header;
	uint16_t ip_header_len;

	if(length < sizeof(struct ip)) {
		SCTP_PRINTF("error: packet too short for IP header!\n");
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
		        usrsctp_netmap_pkt_info_sctp(buffer +ip_header_len, length - ip_header_len, recursive);
		        break;
		    case IPPROTO_UDP:
		        usrsctp_netmap_pkt_info_udp(buffer + ip_header_len, length - ip_header_len, recursive);
		        break;
		    default:
		        printf("\tunknown protocol: %u\n",ip_header->ip_p);
	    }
	}
}

// print sctp info
static void usrsctp_netmap_pkt_info_sctp(char *buffer, uint32_t length, uint8_t recursive) {
	struct sctphdr *sctp_header;

	if (length < sizeof(struct sctphdr)) {
		SCTP_PRINTF("error: packet too short for SCTP header!\n");
		return;
	}
	sctp_header = (struct sctphdr*)buffer;
	SCTP_PRINTF("\t## SCTP\n");
}

// print udp info
static void usrsctp_netmap_pkt_info_udp(char *buffer, uint32_t length, uint8_t recursive) {
	struct udphdr *udp_header;

	if (length < sizeof(struct udphdr)) {
		SCTP_PRINTF("error: packet too short for UDP header!\n");
		return;
	}
	udp_header = (struct udphdr*)buffer;

	SCTP_PRINTF("\t## UDP");
    SCTP_PRINTF("\t:%u", ntohs(udp_header->uh_sport));
    SCTP_PRINTF(" -> ");
    SCTP_PRINTF(":%u\n", ntohs(udp_header->uh_dport));
    //SCTP_PRINTF(" - length %u\n", ntohs(udp_header->uh_ulen));
}


/* ########## PACKET HANDLING SECTION ########## */

static void usrsctp_netmap_handle_ethernet(char* buffer, uint32_t length) {
	struct ether_header *eth_header;

	if (length < sizeof(struct ether_header)) {
        SCTP_PRINTF("error: packet too short for ether_header!\n");
        return;
    };

    eth_header = (struct ether_header*)buffer;

    switch (htons(eth_header->ether_type)) {

    	// handle ARP requests
    	case(ETHERTYPE_ARP):
	    	usrsctp_netmap_handle_arp(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header));
    		break;

    	// handle IP packets
    	case(ETHERTYPE_IP):
    		usrsctp_netmap_handle_ipv4(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header));
    		break;
    }
}

// handle ARP requests
static void usrsctp_netmap_handle_arp(char *buffer, uint32_t length) {

	struct in_addr ip_local;
	struct arp_packet *arp_request;
	struct arp_packet *arp_response;
	struct ether_header *eth_header;
	struct netmap_slot *slot;
	struct netmap_ring *tx_ring;
	char *nmBuf;
	uint32_t cur;

	if(length < sizeof(struct arp_packet)) {
        SCTP_PRINTF("error: packet too short for arp_packet!\n");
        return;
	}

	arp_request = (struct arp_packet*)buffer;

	// should be fine, just in case...
	if(!inet_pton(AF_INET,netmap_ip_src,&ip_local)) {
		SCTP_PRINTF("pton failed!\n");
		return;
	}

	// XXX performance? valid?
	if(!memcmp(&arp_request->dst_ip,&ip_local,4)) {

		tx_ring = NETMAP_TXRING(SCTP_BASE_VAR(netmap_base.iface),0);

		cur = tx_ring->cur;
		if(!nm_ring_empty(tx_ring)) {
			slot = &tx_ring->slot[cur];
			slot->len = sizeof(struct ether_header)+sizeof(struct arp_packet);

			nmBuf = NETMAP_BUF(tx_ring, slot->buf_idx);

			//memset(nmBuf,0,sizeof(struct ether_header)+ip_pkt_len);

			// build ARP request - quite ugly..
			arp_response = (struct arp_packet*)(nmBuf + sizeof(struct ether_header));
			arp_response->hardware_type	= htons(1);
			arp_response->hardware_type	= htons(1);
			arp_response->protocol_type	= htons(2048);
			arp_response->hardware_size	= 6;
			arp_response->protocol_size	= 4;
			arp_response->operation		= htons(2);
			//arp_request.src_mac			=
			arp_response->src_ip			= *(uint32_t*)&ip_local;
			//arp_request.dst_mac			= arp_packet->src_mac;
			arp_response->dst_ip			= arp_request->src_ip;
			memcpy(arp_response->src_mac, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
			memcpy(arp_response->dst_mac, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);


			// fill ethernet header
			eth_header = (struct ether_header*)nmBuf;
			eth_header->ether_type = htons(ETHERTYPE_ARP);
			memcpy(eth_header->ether_shost, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
			memcpy(eth_header->ether_dhost, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

			cur = nm_ring_next(tx_ring, cur);
			tx_ring->head = tx_ring->cur = cur;
			ioctl(SCTP_BASE_VAR(netmap_base.fd), NIOCTXSYNC, NULL);
		} else {
			SCTP_PRINTF("arp - no space left in ring\n");
		}
	}
}

// handle ip
static void usrsctp_netmap_handle_ipv4(char *buffer, uint32_t length) {
	struct ip *ip_header;
	uint16_t ip_header_length;
	uint16_t ip_total_length;

	if(length < sizeof(struct ip)) {
		SCTP_PRINTF("error: packet too short for ip_packet!\n");
		return;
	}

	ip_header = (struct ip*)buffer;
	ip_header_length = ((ip_header->ip_hl & 0xf) * 4);
	ip_total_length = ntohs(ip_header->ip_len);

	if(ip_header_length > length || ip_header_length > length || ip_header_length > ip_total_length) {
		SCTP_PRINTF("error: ip length mismatch");
		return;
	}

	switch (ip_header->ip_p) {
	    case IPPROTO_SCTP:
	        usrsctp_netmap_handle_sctp(buffer + ip_header_length, ip_total_length - ip_header_length, ip_header, 0);
	        break;
	    case IPPROTO_UDP:
	        usrsctp_netmap_handle_udp(buffer + ip_header_length, ip_total_length - ip_header_length, ip_header);
	        break;
    }

}

// handle sctp packets
static void usrsctp_netmap_handle_sctp(char *buffer, uint32_t length, struct ip *ip_header, uint16_t udp_encaps_port) {

	struct sockaddr_in src, dst;
	struct mbuf *m;
	struct sctphdr *sh;
	struct sctp_chunkhdr *ch;
	//struct ip* ip_header;
	int ecn = 0;
#if !defined(SCTP_WITH_NO_CSUM)
	int compute_crc = 1;
#endif

	//SCTP_PRINTF(" <<< SCTP - length: %u\n",length);

	memset(&src, 0, sizeof(struct sockaddr_in));
	memset(&dst, 0, sizeof(struct sockaddr_in));

	//ip_header = (struct ip*)buffer;

	SCTP_STAT_INCR(sctps_recvpackets);
	SCTP_STAT_INCR_COUNTER64(sctps_inpackets);

	if ((m = sctp_get_mbuf_for_msg(length, 1, M_NOWAIT, 0, MT_DATA)) == NULL) {
		SCTP_PRINTF("get mbuf failed!");
		return;
	}

	m_copyback(m, 0, length, (caddr_t)buffer);

	if (SCTP_BUF_LEN(m) < (int)(sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr))) {
		if ((m = m_pullup(m, sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr))) == NULL) {
			SCTP_STAT_INCR(sctps_hdrops);
			return;
		}
	}

	sh = mtod(m, struct sctphdr *);;
	ch = (struct sctp_chunkhdr *)((caddr_t)sh + sizeof(struct sctphdr));


	if (ip_header->ip_tos != 0) {
		ecn = ip_header->ip_tos & 0x02;
	}

	dst.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	dst.sin_len = sizeof(struct sockaddr_in);
#endif
	dst.sin_addr = ip_header->ip_dst;
	dst.sin_port = sh->dest_port;

	src.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	src.sin_len = sizeof(struct sockaddr_in);
#endif
	src.sin_addr = ip_header->ip_src;
	src.sin_port = sh->src_port;

	/* SCTP does not allow broadcasts or multicasts */
	if (IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
		m_freem(m);
		return;
	}
	if (SCTP_IS_IT_BROADCAST(dst.sin_addr, m)) {
		m_freem(m);
		return;
	}
	

#if defined(SCTP_WITH_NO_CSUM)
	SCTP_STAT_INCR(sctps_recvnocrc);
#else
	if (src.sin_addr.s_addr == dst.sin_addr.s_addr) {
		compute_crc = 0;
		SCTP_STAT_INCR(sctps_recvnocrc);
	} else {
		SCTP_STAT_INCR(sctps_recvswcrc);
	}
#endif

	sctp_common_input_processing(&m, 0, sizeof(struct sctphdr), length, (struct sockaddr *)&src, (struct sockaddr *)&dst, sh, ch,
#if !defined(SCTP_WITH_NO_CSUM)
	                             1,
#endif
	                             ecn,SCTP_DEFAULT_VRFID, udp_encaps_port);

	if (m) {
		sctp_m_freem(m);
	}
}

// handle udp
static void usrsctp_netmap_handle_udp(char *buffer, uint32_t length, struct ip *ip_header) {
	struct udphdr *udp_header;

	if(length < sizeof(struct udphdr)) {
		SCTP_PRINTF("error: packet too short for udp_header!\n");
		return;
	}

	udp_header = (struct udphdr*)buffer;

	if (ntohs(udp_header->uh_dport) == SCTP_BASE_SYSCTL(sctp_udp_tunneling_port)) {
		usrsctp_netmap_handle_sctp(buffer + sizeof(struct udphdr),length - sizeof(struct udphdr),ip_header, udp_header->uh_sport);
	} else {
		SCTP_PRINTF("netmap - discarding udp packet - wrong port: %u\n",ntohs(udp_header->uh_dport));
	}
}

// function for receive thread
// xxx errorhandling
void *usrsctp_netmap_recv_function(void *arg) {
	struct sctp_netmap_base *netmap;
	struct pollfd pfd;
	struct netmap_ring *ring;
	uint32_t ring_index;
	uint32_t cur;
	uint32_t buf_idx;
	uint32_t buf_len;
	uint32_t rx_ring_index;
	char *buf;

	if(netmap_debug_operation) {
		SCTP_PRINTF("netmap - receive thread started\n");
	}

	netmap = &SCTP_BASE_VAR(netmap_base);

	pfd.fd = netmap->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    rx_ring_index = 0;


	while (1) {
        poll(&pfd, 1, -1);

        ring_index = rx_ring_index;

    	do {
        	/* compute current ring to use */
        	ring = NETMAP_RXRING(netmap->iface, ring_index);

	        if (!nm_ring_empty(ring)) {
	            cur = ring->cur;
	            buf_idx = ring->slot[cur].buf_idx;
	            buf = NETMAP_BUF(ring, buf_idx);
	            buf_len = ring->slot[cur].len;

	            if(netmap_debug_operation) {
	            	SCTP_PRINTF("netmap - incoming packet <<<\n");
	            }

	            if(netmap_debug_pkts) {
	            	usrsctp_netmap_pkt_info_ethernet(buf,buf_len,1);
	            }

	            if(netmap_debug_hexdump) {
	            	usrsctp_netmap_hexdump("SCTP <<< ",buf,buf_len);
	            }

	            usrsctp_netmap_handle_ethernet(buf,buf_len);

	            ring->cur = nm_ring_next(ring, cur);
	            ring->head = ring->cur;
	            rx_ring_index = ring_index;
	        }

	        ring_index++;
	        if (ring_index == netmap->iface->ni_rx_rings) {
	            ring_index = 0;
	        }

	    } while (ring_index != rx_ring_index);
    }
	return (NULL);
}


// copy data from mbuf chain in netmap tx ring

void usrsctp_netmap_ip_output(int *result, struct mbuf *o_pak) {

	struct ether_header *eth_header;
	struct ip *ip_header;
	struct netmap_slot *slot;
	struct netmap_ring *tx_ring;
	char *nmBuf;
	uint32_t cur, ip_pkt_len;

	ip_pkt_len = sctp_calculate_len(o_pak);
	tx_ring = NETMAP_TXRING(SCTP_BASE_VAR(netmap_base.iface),0);

	// return if packet is too big
	if(tx_ring->nr_buf_size < ip_pkt_len + sizeof(struct ether_header)) {
		*result = ENOBUFS;
		return;
	}

	cur = tx_ring->cur;
	if(!nm_ring_empty(tx_ring)) {
		slot = &tx_ring->slot[cur];
		slot->len = sizeof(struct ether_header)+ip_pkt_len;

		nmBuf = NETMAP_BUF(tx_ring, slot->buf_idx);

		memset(nmBuf,0,sizeof(struct ether_header)+ip_pkt_len);
		//m_pullup(o_pak,ip_pkt_len);
		m_copydata(o_pak, 0, ip_pkt_len, nmBuf + sizeof(struct ether_header));

		// fill ethernet header
		eth_header = (struct ether_header*)nmBuf;
		eth_header->ether_type = htons(ETHERTYPE_IP);
		memcpy(eth_header->ether_shost, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
		memcpy(eth_header->ether_dhost, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

		// correct ip header len
		ip_header = (struct ip*)(nmBuf + sizeof(struct ether_header));
		// override outgoing ip?
		if(netmap_ip_override) {
			inet_pton(AF_INET, netmap_ip_dst, &ip_header->ip_dst);
			inet_pton(AF_INET, netmap_ip_src, &ip_header->ip_src);
		}
		ip_header->ip_len = htons(ip_header->ip_len);
		ip_header->ip_off = 0;
		ip_header->ip_sum = usrsctp_netmap_ip_wrapsum(usrsctp_netmap_ip_checksum(ip_header, sizeof(struct ip), 0));

		if(netmap_debug_operation) {
			SCTP_PRINTF("netmap - packet >>> %u byte \n",slot->len);
		}

		if(netmap_debug_pkts) {
			usrsctp_netmap_pkt_info_ethernet(nmBuf,slot->len,1);
		}

		if(netmap_debug_hexdump) {
			usrsctp_netmap_hexdump("SCTP >>> ",nmBuf,slot->len);
		}

		cur = nm_ring_next(tx_ring, cur);
		tx_ring->head = tx_ring->cur = cur;
		ioctl(SCTP_BASE_VAR(netmap_base.fd), NIOCTXSYNC, NULL);

	} else {
		*result = ENOBUFS;
		SCTP_PRINTF("netmap - no space left in ring\n");
	}
}


// Prepare netmap interface
int usrsctp_netmap_init() {
	struct sctp_netmap_base* netmap_base;
	netmap_base = &SCTP_BASE_VAR(netmap_base);

	memset(&netmap_base->req,0,sizeof(struct nmreq));
	strcpy(netmap_base->req.nr_name, netmap_ifname);
	netmap_base->req.nr_version = NETMAP_API;
    netmap_base->req.nr_flags = NR_REG_ALL_NIC;

    SCTP_PRINTF("netmap - local UDP port: %u\n",SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));

	if((netmap_base->fd = open("/dev/netmap", O_RDWR)) == -1) {
		SCTP_PRINTF("netmap - open failed for: %s\n",netmap_base->req.nr_name);
		return -1;
	}

	if (ioctl(netmap_base->fd, NIOCREGIF, &netmap_base->req)) {
		SCTP_PRINTF("netmap - ioctl NIOCREGIF failed\n");
		return -1;
	}

#if defined(MULTISTACK)
    SCTP_PRINTF("netmap - running in MULTISTACK mode\n");
    struct sockaddr_in sin;

    //so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ((netmap_base->so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        return -1;
    }
    SCTP_PRINTF("multistack - socket\n");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(multistack_port);
    //sin.sin_addr.s_addr = htonl(g.src_ip.start);
	if(!inet_pton(AF_INET, netmap_ip_src, &sin.sin_addr.s_addr)){
		printf("error: invalid local address\n");
		return -1;
	}
    if (bind(netmap_base->so, (struct sockaddr *)&sin, sizeof(sin))) {
        perror("multistack - bind");
        close(netmap_base->so);
        return -1;
    }
    SCTP_PRINTF("multistack - bind\n");
    strncpy(netmap_base->msr.mr_name, netmap_base->req.nr_name, sizeof(netmap_base->msr.mr_name));
    netmap_base->msr.mr_cmd = MULTISTACK_BIND;
    netmap_base->msr.mr_sin = sin;
    netmap_base->msr.mr_proto = IPPROTO_UDP;

    printf("%p\n",&netmap_base->msr);

    if (ioctl(netmap_base->fd, NIOCCONFIG, &netmap_base->msr) == -1) {
        perror("multistack - ioctl");
        return -1;
    }

#endif /* MULTISTACK */

	if((netmap_base->mem = mmap(0, netmap_base->req.nr_memsize, PROT_WRITE | PROT_READ, MAP_SHARED, netmap_base->fd, 0)) == (void *) -1){
		SCTP_PRINTF("netmap - mmap failed\n");
		return -1;
	}

	netmap_base->iface = NETMAP_IF(netmap_base->mem, netmap_base->req.nr_offset);

	SCTP_PRINTF("netmap init complete\n");
	return 0;
}

int usrsctp_netmap_close() {
	struct netmap_ring *tx_ring;
	tx_ring = NETMAP_TXRING(SCTP_BASE_VAR(netmap_base.iface),0);
	while (nm_tx_pending(tx_ring)) {
		ioctl(SCTP_BASE_VAR(netmap_base.fd), NIOCTXSYNC, NULL);
		usleep(1); /* wait 1 tick */
		SCTP_PRINTF("waiting... \n");
	}

#ifdef MULTISTACK
	SCTP_BASE_VAR(netmap_base.msr.mr_cmd) = MULTISTACK_UNBIND;
	if (ioctl(SCTP_BASE_VAR(netmap_base.fd), NIOCCONFIG, &SCTP_BASE_VAR(netmap_base.msr)) == -1) {
		perror("multistack - ioctl");
		SCTP_PRINTF("raus\n");
		return -1;
	}

	if (close(SCTP_BASE_VAR(netmap_base.so))) {
		perror("multistack - close");
		return -1;
	}
#endif

	// closes the file descriptor
	if (munmap(SCTP_BASE_VAR(netmap_base.mem), SCTP_BASE_VAR(netmap_base.req.nr_memsize))) {
		SCTP_PRINTF("error - munmap failed\n");
		return -1;
	}

	if (close(SCTP_BASE_VAR(netmap_base.fd))) {
		perror("netmap - close");
		return -1;
	}

	SCTP_PRINTF("netmap - closed successfully...\n");

	return 0;

}

#endif //defined(NETMAP) || defined(MULTISTACK)

