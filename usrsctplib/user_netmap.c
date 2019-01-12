#include <stdio.h>

#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <net/ethernet.h>

#include <sys/mman.h>
#include <user_mbuf.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <netinet/udp.h>
#include <netinet/sctp_input.h>

#include "user_netmap_config.h"
#define MAXLEN_MBUF_CHAIN 32
#define NETMAP_WITH_LIBS

#if defined(__Userspace_os_FreeBSD)
#define __FreeBSD__
#endif

#include <net/netmap_user.h>

#if defined(__Userspace_os_FreeBSD)
#undef __FreeBSD__
#endif

#include <user_mbuf.h>

enum netmap_states {NETMAP_S_CLOSED, NETMAP_S_OPENING, NETMAP_S_OPEN, NETMAP_S_CLOSING};

struct sctp_netmap_base {
	enum netmap_states state;
	struct nm_desc *desc;
	char if_string[100];
	struct netmap_if *iface;
};

static uint16_t ip_checksum(const char *data, size_t length);
static void 	handle_ethernet(const char* buffer, size_t length);
static void 	handle_ipv4(const char *buffer, size_t length);
static void 	handle_sctp(const char *buffer, size_t length, struct ip *ip_header, uint16_t udp_encaps_port);
static void 	handle_udp(const char *buffer, size_t length, struct ip *ip_header);
static void 	handle_arp(const char *buffer, size_t length);

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


/* Compute the checksum of the given ip header. */
static uint16_t ip_checksum(const char* data, size_t length) {
	// Initialise the accumulator.
	uint64_t acc = 0xffff;
	// Handle any partial block at the start of the data.
	unsigned int offset = ((uintptr_t)data) & 3;

	if (offset) {
		size_t count = 4 - offset;
		if (count > length) {
			count = length;
		}
		uint32_t word = 0;
		memcpy(offset + (char*) &word, data, count);
		acc += ntohl(word);
		data += count;
		length -= count;
	}

	// Handle any complete 32-bit blocks.
	const char* data_end = data + (length& ~ 3);
	while (data != data_end) {
		uint32_t word;
		memcpy(&word, data, 4);
		acc += ntohl(word);
		data += 4;
	}
	length &= 3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word = 0;
		memcpy(&word, data, length);
		acc += ntohl(word);
	}

	// Handle deferred carries.
	acc = (acc & 0xffffffff) + (acc >> 32);
	while (acc >> 16) {
		acc = (acc & 0xffff) + (acc >> 16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset & 1) {
		acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}



/* ########## PACKET HANDLING SECTION ########## */

static void handle_ethernet(const char* buffer, size_t length) {
	struct ether_header *eth_header;

	if (length < sizeof(struct ether_header)) {
		SCTP_PRINTF("error: packet too short for ether_header!\n");
		return;
	};

	eth_header = (struct ether_header*) buffer;

	switch (htons(eth_header->ether_type)) {
		// handle ARP requests
		case(ETHERTYPE_ARP):
			handle_arp(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header));
			break;

		// handle IP packets
		case(ETHERTYPE_IP):
			handle_ipv4(buffer + sizeof(struct ether_header), length - sizeof(struct ether_header));
			break;
	}
}

// handle ARP requests and respond
static void handle_arp(const char *buffer, size_t length) {

	struct in_addr ip_local;
	struct arp_packet *arp_request;
	struct arp_packet *arp_response;
	struct ether_header *eth_header;
	struct netmap_slot *slot;
	struct netmap_ring *tx_ring;
	char *tx_slot_buffer;
	uint32_t cur;
	struct sctp_netmap_base* netmap_base;

	netmap_base = SCTP_BASE_VAR(netmap_base);

	if (length < sizeof(struct arp_packet)) {
		SCTP_PRINTF("error: packetsize too small for arp!\n");
		return;
	}

	arp_request = (struct arp_packet*)buffer;

	// should be fine, just in case...
	if (!inet_pton(AF_INET, netmap_ip_src, &ip_local)) {
		SCTP_PRINTF("pton failed!\n");
		return;
	}

	// Is this request for me? // XXX performance? valid?

	if (!memcmp(&arp_request->dst_ip, &ip_local, 4)) {

		tx_ring = NETMAP_TXRING(netmap_base->iface, 0);
		cur = tx_ring->cur;

		if(!nm_ring_empty(tx_ring)) {
			slot = &tx_ring->slot[cur];
			slot->len = sizeof(struct ether_header) + sizeof(struct arp_packet);

			tx_slot_buffer = NETMAP_BUF(tx_ring, slot->buf_idx);
			memset(tx_slot_buffer, 0, sizeof(struct ether_header) + sizeof(struct ether_header));

			// build ARP request - quite ugly..
			arp_response = (struct arp_packet*)(tx_slot_buffer + sizeof(struct ether_header));
			arp_response->hardware_type	= htons(1);
			arp_response->hardware_type	= htons(1);
			arp_response->protocol_type	= htons(2048);
			arp_response->hardware_size	= 6;
			arp_response->protocol_size	= 4;
			arp_response->operation		= htons(2);
			arp_response->src_ip		= *(uint32_t*) &ip_local;
			arp_response->dst_ip		= arp_request->src_ip;
			memcpy(arp_response->src_mac, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
			memcpy(arp_response->dst_mac, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

			// fill ethernet header
			eth_header = (struct ether_header*) tx_slot_buffer;
			eth_header->ether_type = htons(ETHERTYPE_ARP);
			memcpy(eth_header->ether_shost, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
			memcpy(eth_header->ether_dhost, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

			cur = nm_ring_next(tx_ring, cur);
			tx_ring->head = tx_ring->cur = cur;
			ioctl(SCTP_BASE_VAR(netmap_fd), NIOCTXSYNC, NULL);
		} else {
			SCTP_PRINTF("arp - no space left in ring\n");
		}
	}
}

// handle ip
static void handle_ipv4(const char *buffer, size_t length) {
	struct ip *ip_header;
	uint16_t ip_header_length;
	uint16_t ip_total_length;

	if (length < sizeof(struct ip)) {
		SCTP_PRINTF("error: packetsize too small for an ip packet!\n");
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
			handle_sctp(buffer + ip_header_length, ip_total_length - ip_header_length, ip_header, 0);
			break;
		case IPPROTO_UDP:
			handle_udp(buffer + ip_header_length, ip_total_length - ip_header_length, ip_header);
			break;
	}

}

// handle sctp packets
static void handle_sctp(const char *buffer, size_t length, struct ip *ip_header, uint16_t udp_encaps_port) {

	struct sockaddr_in src, dst;
	struct mbuf *m;
	struct sctphdr *sctp_header;
	struct sctp_chunkhdr *chunk_header;
	//struct ip* ip_header;
	int ecn = 0;
#if !defined(SCTP_WITH_NO_CSUM)
	int compute_crc = 1;
#endif

	memset(&src, 0, sizeof(struct sockaddr_in));
	memset(&dst, 0, sizeof(struct sockaddr_in));

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

	sctp_header = mtod(m, struct sctphdr *);
	chunk_header = (struct sctp_chunkhdr *)((unsigned char *)sctp_header + sizeof(struct sctphdr));

	if (ip_header->ip_tos != 0) {
		ecn = ip_header->ip_tos & 0x02;
	}

	// destination
	dst.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	dst.sin_len = sizeof(struct sockaddr_in);
#endif
	dst.sin_addr = ip_header->ip_dst;
	dst.sin_port = sctp_header->dest_port;

	// source
	src.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
	src.sin_len = sizeof(struct sockaddr_in);
#endif
	src.sin_addr = ip_header->ip_src;
	src.sin_port = sctp_header->src_port;

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
	SCTP_STAT_INCR(sctps_recv_spare);
#else
	if (src.sin_addr.s_addr == dst.sin_addr.s_addr) {
		compute_crc = 0;
		SCTP_STAT_INCR(sctps_recv_spare);
	} else {
		SCTP_STAT_INCR(sctps_recvswcrc);
	}
#endif

	sctp_common_input_processing(&m, 0, sizeof(struct sctphdr), length, (struct sockaddr *)&src, (struct sockaddr *)&dst, sctp_header, chunk_header,
#if !defined(SCTP_WITH_NO_CSUM)
								 1,
#endif
								 ecn,SCTP_DEFAULT_VRFID, udp_encaps_port);

	if (m) {
		sctp_m_freem(m);
	}
}

// handle udp
static void handle_udp(const char *buffer, size_t length, struct ip *ip_header) {
	struct udphdr *udp_header;

	if(length < sizeof(struct udphdr)) {
		SCTP_PRINTF("error: packet too short for udp_header!\n");
		return;
	}

	udp_header = (struct udphdr*)buffer;

	if (ntohs(udp_header->uh_dport) == SCTP_BASE_SYSCTL(sctp_udp_tunneling_port)) {
		handle_sctp(buffer + sizeof(struct udphdr),length - sizeof(struct udphdr),ip_header, udp_header->uh_sport);
	} else {
		SCTP_PRINTF("netmap - discarding udp packet - wrong port: %u\n",ntohs(udp_header->uh_dport));
	}
}

// function for receive thread
// xxx errorhandling
void *usrsctp_netmap_recv_function(void *arg) {
	struct sctp_netmap_base *netmap_base;
	struct pollfd pfd;
	u_char *pkt_buf;
	struct	nm_pkthdr pkt_hdr;

	if(netmap_debug_operation) {
		SCTP_PRINTF("netmap - receive thread started - pid: %u\n",getpid());
	}

	netmap_base = SCTP_BASE_VAR(netmap_base);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = NETMAP_FD(netmap_base->desc);
	pfd.events = POLLIN;

	while (netmap_base->state == NETMAP_S_OPEN) {
		poll(&pfd, 1, -1);
		if (pfd.revents != POLLIN) {
			continue;
		}

		while ((pkt_buf = nm_nextpkt(netmap_base->desc, &pkt_hdr))) {
			handle_ethernet((char *)pkt_buf, pkt_hdr.len);
		}
	}

	printf("usrsctp_netmap_recv_function - exiting... \n");
	return (NULL);
}


// copy data from mbuf chain in netmap tx ring

void usrsctp_netmap_ip_output(int *result, struct mbuf *o_pak) {

	struct ether_header *eth_header;
	struct ip *ip_header;
	size_t ip_pkt_len;
	struct sctp_netmap_base *netmap_base;
	char *pkt_buf;

	netmap_base = SCTP_BASE_VAR(netmap_base);

	if (netmap_base->state != NETMAP_S_OPEN) {
		SCTP_PRINTF("usrsctp_netmap_ip_output - ERROR: netmap state not open!");
		exit(-1);
	}

	ip_pkt_len = sctp_calculate_len(o_pak);

	pkt_buf = malloc(sizeof(struct ether_header) + ip_pkt_len);

	m_copydata(o_pak, 0, ip_pkt_len, pkt_buf + sizeof(struct ether_header));

	// fill ethernet header
	eth_header = (struct ether_header*) pkt_buf;
	eth_header->ether_type = htons(ETHERTYPE_IP);
	memcpy(eth_header->ether_shost, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

	// correct ip header len
	ip_header = (struct ip*)(pkt_buf + sizeof(struct ether_header));
	// override outgoing ip?
	if(netmap_ip_override) {
		inet_pton(AF_INET, netmap_ip_dst, &ip_header->ip_dst);
		inet_pton(AF_INET, netmap_ip_src, &ip_header->ip_src);
	}
	ip_header->ip_len = htons(ip_header->ip_len);
	ip_header->ip_off = 0;
	ip_header->ip_sum = ip_checksum((char *)ip_header, sizeof(struct ip));

	if (!nm_inject(netmap_base->desc, pkt_buf, sizeof(struct ether_header) + ip_pkt_len)) {
		SCTP_PRINTF("netmap - %s - nm_inject() failed\n", __func__);
	}
	ioctl(NETMAP_FD(netmap_base->desc), NIOCTXSYNC, 0);

	if (netmap_debug_operation) {
		SCTP_PRINTF("netmap - packet >>> %u byte \n", sizeof(struct ether_header) + ip_pkt_len);
	}

#if defined(NETMAP_DEBUG)
		printf("DEBUG!\n");
		netmap_pktinfo(tx_slot_buffer, ip_pkt_len, 1, 1);
#endif
}


// Prepare netmap interface
int usrsctp_netmap_init() {
	struct sctp_netmap_base* netmap_base;

	SCTP_BASE_VAR(netmap_base) = malloc(sizeof(struct sctp_netmap_base));
	netmap_base = SCTP_BASE_VAR(netmap_base);
	memset(netmap_base, 0, sizeof(struct sctp_netmap_base));

	netmap_base->state = NETMAP_S_OPENING;

	snprintf(netmap_base->if_string, sizeof(netmap_base->if_string), "netmap:%s", netmap_ifname);
	printf("netmap interface: %s\n", netmap_base->if_string);

	netmap_base->desc = nm_open(netmap_base->if_string, NULL, 0, NULL);

	SCTP_PRINTF("netmap - local UDP port: %u\n", SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));

	netmap_base->state = NETMAP_S_OPEN;
	SCTP_PRINTF("netmap init complete - p : %p - fd : %d\n", SCTP_BASE_VAR(netmap_base), SCTP_BASE_VAR(netmap_fd));
	return 0;
}


int usrsctp_netmap_close() {
	struct netmap_ring *tx_ring;
	struct sctp_netmap_base *netmap_base;

	netmap_base = SCTP_BASE_VAR(netmap_base);
	netmap_base->state = NETMAP_S_CLOSING;

	SCTP_PRINTF("flushing outgoing packets\n");
	tx_ring = NETMAP_TXRING(netmap_base->iface, 0);
	while (nm_tx_pending(tx_ring)) {
		ioctl(SCTP_BASE_VAR(netmap_fd), NIOCTXSYNC, NULL);
		usleep(100); /* wait 1 tick */
		SCTP_PRINTF("waiting... \n");
	}

	SCTP_PRINTF("waiting for receive thread...\n");
	pthread_join(SCTP_BASE_VAR(recvthreadnetmap), NULL);
	SCTP_PRINTF("done\n");

	netmap_base->state = NETMAP_S_CLOSED;
	SCTP_PRINTF("netmap - closed successfully...\n");

	return 0;
}
