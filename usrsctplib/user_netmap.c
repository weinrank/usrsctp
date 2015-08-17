#define NETMAP_DEBUG
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
#include <arpa/inet.h>
#include <sys/poll.h>
#include <netinet/udp.h>
#include <netinet/sctp_input.h>

/* ########## CONFIG SECTION ########## */

#ifdef NETMAP_DEBUG
#include "netmap_debug.h"
#endif

#if defined(MULTISTACK)
static const char *netmap_ifname = "valem:usrsctp1";
static const uint16_t multistack_port = 9899;
#else
static const char *netmap_ifname = "igb1";
#endif

static const char *netmap_mac_src = "08:00:27:12:0d:e1";
static const char *netmap_mac_dst = "0a:00:27:00:00:01";

static const int netmap_ip_override = 0;
static const char *netmap_ip_src = "192.168.57.2";
static const char *netmap_ip_dst = "192.168.57.1";

static const uint8_t thread_closed = 0;


static const int netmap_debug_operation = 1;
#if defined(NETMAP_DEBUG)
static const int netmap_debug_packet_info = 1;
static const int netmap_debug_packet_dump = 0;
#endif // defined(NETMAP_DEBUG)


#define MAXLEN_MBUF_CHAIN 32

/* ########## CONFIG SECTION END ########## */

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
static uint16_t ip_checksum(const char* data,size_t length) {
    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    const char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
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

    eth_header = (struct ether_header*)buffer;

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

	if(length < sizeof(struct arp_packet)) {
        SCTP_PRINTF("error: packetsize too small for arp!\n");
        return;
	}

	arp_request = (struct arp_packet*)buffer;

	// should be fine, just in case...
	if(!inet_pton(AF_INET,netmap_ip_src,&ip_local)) {
		SCTP_PRINTF("pton failed!\n");
		return;
	}

	// Is this request for me? // XXX performance? valid?

	if(!memcmp(&arp_request->dst_ip,&ip_local,4)) {

		tx_ring = NETMAP_TXRING(SCTP_BASE_VAR(netmap_base.iface),0);
		cur = tx_ring->cur;

		if(!nm_ring_empty(tx_ring)) {
			slot = &tx_ring->slot[cur];
			slot->len = sizeof(struct ether_header)+sizeof(struct arp_packet);

			tx_slot_buffer = NETMAP_BUF(tx_ring, slot->buf_idx);
			memset(tx_slot_buffer,0,sizeof(struct ether_header)+sizeof(struct ether_header));

			// build ARP request - quite ugly..
			arp_response = (struct arp_packet*)(tx_slot_buffer + sizeof(struct ether_header));
			arp_response->hardware_type	= htons(1);
			arp_response->hardware_type	= htons(1);
			arp_response->protocol_type	= htons(2048);
			arp_response->hardware_size	= 6;
			arp_response->protocol_size	= 4;
			arp_response->operation		= htons(2);
			arp_response->src_ip		= *(uint32_t*)&ip_local;
			arp_response->dst_ip		= arp_request->src_ip;
			memcpy(arp_response->src_mac, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
			memcpy(arp_response->dst_mac, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);


			// fill ethernet header
			eth_header = (struct ether_header*)tx_slot_buffer;
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
static void handle_ipv4(const char *buffer, size_t length) {
	struct ip *ip_header;
	uint16_t ip_header_length;
	uint16_t ip_total_length;

	if(length < sizeof(struct ip)) {
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

	sctp_header = mtod(m, struct sctphdr *); // doppeltes simikolon
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
	SCTP_STAT_INCR(sctps_recvnocrc);
#else
	if (src.sin_addr.s_addr == dst.sin_addr.s_addr) {
		compute_crc = 0;
		SCTP_STAT_INCR(sctps_recvnocrc);
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
	struct sctp_netmap_base *netmap;
	struct pollfd pfd;
	struct netmap_ring *ring;
	uint32_t ring_index;
	uint32_t cur;
	uint32_t buf_idx;
	size_t rx_slot_length;
	uint32_t rx_ring_index;
	char *rx_slot_buffer;

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
	            rx_slot_buffer = NETMAP_BUF(ring, buf_idx);
	            rx_slot_length = ring->slot[cur].len;



	            if(netmap_debug_operation) {
	            	SCTP_PRINTF("netmap - incoming packet <<<\n");
	            }

				#if defined(NETMAP_DEBUG)
					netmap_pktinfo(rx_slot_buffer,rx_slot_length,netmap_debug_packet_info,netmap_debug_packet_dump);
				#endif

	            handle_ethernet(rx_slot_buffer,rx_slot_length);

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
	char *tx_slot_buffer;
	uint32_t cur;
	size_t ip_pkt_len;

	ip_pkt_len = sctp_calculate_len(o_pak);
	tx_ring = NETMAP_TXRING(SCTP_BASE_VAR(netmap_base.iface),0);

	// return if packet is too big
	if(tx_ring->nr_buf_size < (ip_pkt_len + sizeof(struct ether_header))) {
		*result = ENOBUFS;
		return;
	}

	cur = tx_ring->cur;
	if(!nm_ring_empty(tx_ring)) {
		slot = &tx_ring->slot[cur];
		slot->len = sizeof(struct ether_header)+ip_pkt_len;

		tx_slot_buffer = NETMAP_BUF(tx_ring, slot->buf_idx);

		memset(tx_slot_buffer,0,sizeof(struct ether_header)+ip_pkt_len);
		//m_pullup(o_pak,ip_pkt_len);
		m_copydata(o_pak, 0, ip_pkt_len, tx_slot_buffer + sizeof(struct ether_header));

		// fill ethernet header
		eth_header = (struct ether_header*)tx_slot_buffer;
		eth_header->ether_type = htons(ETHERTYPE_IP);
		memcpy(eth_header->ether_shost, ether_aton(netmap_mac_src), ETHER_ADDR_LEN);
		memcpy(eth_header->ether_dhost, ether_aton(netmap_mac_dst), ETHER_ADDR_LEN);

		// correct ip header len
		ip_header = (struct ip*)(tx_slot_buffer + sizeof(struct ether_header));
		// override outgoing ip?
		if(netmap_ip_override) {
			inet_pton(AF_INET, netmap_ip_dst, &ip_header->ip_dst);
			inet_pton(AF_INET, netmap_ip_src, &ip_header->ip_src);
		}
		ip_header->ip_len = htons(ip_header->ip_len);
		ip_header->ip_off = 0;
		ip_header->ip_sum = ip_checksum((char *)ip_header, sizeof(struct ip));

		if(netmap_debug_operation) {
			SCTP_PRINTF("netmap - packet >>> %u byte \n",slot->len);
		}

#if defined(NETMAP_DEBUG)
		printf("DEBUG!\n");
		netmap_pktinfo(tx_slot_buffer,ip_pkt_len,1,1);
#endif

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

	// null struct and copy interace name
	memset(&netmap_base->req,0,sizeof(struct nmreq));
	strcpy(netmap_base->req.nr_name, netmap_ifname);

    SCTP_PRINTF("netmap - local UDP port: %u\n",SCTP_BASE_SYSCTL(sctp_udp_tunneling_port));

	if((netmap_base->fd = open("/dev/netmap", O_RDWR)) == -1) {
		SCTP_PRINTF("netmap - open failed for: %s - run as root?\n",netmap_base->req.nr_name);
		return -1;
	}

	netmap_base->req.nr_version = NETMAP_API;
    //netmap_base->req.nr_flags = NR_REG_ALL_NIC;

	if (ioctl(netmap_base->fd, NIOCREGIF, &netmap_base->req)) {
		SCTP_PRINTF("netmap - ioctl NIOCREGIF failed\n");
		return -1;
	}

	#if defined(NETMAP_DEBUG)
		printf("DEBUG!\n");
	#endif

	// prepare outgoing ethernet header



#if defined(MULTISTACK)
    SCTP_PRINTF("netmap - running in MULTISTACK mode\n");

	memset(&netmap_base->ms_sin,0,sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	netmap_base->ms_sin.sin_len = sizeof(struct sockaddr_in);
#endif


    if ((netmap_base->ms_so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        return -1;
    }
    SCTP_PRINTF("multistack - socket\n");

    netmap_base->ms_sin.sin_family = AF_INET;
    netmap_base->ms_sin.sin_port = htons(multistack_port);
#ifdef HAVE_SIN_LEN
	netmap_base->ms_sin.sin_len = sizeof(struct sockaddr_in);
#endif
    //sin.sin_addr.s_addr = htonl(g.src_ip.start);
	if(!inet_pton(AF_INET, netmap_ip_src, &(netmap_base->ms_sin.sin_addr))){
		printf("error: invalid local address\n");
		return -1;
	}
    if (bind(netmap_base->ms_so, (struct sockaddr *)&(netmap_base->ms_sin), sizeof(struct sockaddr_in))) {
        perror("multistack - bind");
        close(netmap_base->ms_so);
        return -1;
    }
    SCTP_PRINTF("multistack - bind\n");

	strcpy(netmap_base->ms_req.mr_name, netmap_ifname);
    netmap_base->ms_req.mr_cmd = MULTISTACK_BIND;
    netmap_base->ms_req.mr_sin = netmap_base->ms_sin;
    netmap_base->ms_req.mr_proto = IPPROTO_UDP;

    if (ioctl(netmap_base->fd, NIOCCONFIG, &(netmap_base->ms_req)) == -1) {
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
	SCTP_BASE_VAR(netmap_base.ms_req.mr_cmd) = MULTISTACK_UNBIND;
	if (ioctl(SCTP_BASE_VAR(netmap_base.fd), NIOCCONFIG, &SCTP_BASE_VAR(netmap_base.ms_req)) == -1) {
		perror("multistack - ioctl");
		SCTP_PRINTF("raus\n");
		return -1;
	}

	if (close(SCTP_BASE_VAR(netmap_base.ms_so))) {
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
