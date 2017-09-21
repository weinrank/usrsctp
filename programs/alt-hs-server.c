/*
 * Copyright (C) 2011-2013 Michael Tuexen
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Usage: alt-hs-server
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <usrsctp.h>

#define PORT 80
#define BUFFER_SIZE 10240
#define SLEEP 1

char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello world\r\n";


void
debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

int
main(int argc, char *argv[])
{
	struct socket *sock;
	struct sockaddr_in6 addr;
	struct sctp_udpencaps encaps;
	struct sctp_event event;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
	                          SCTP_PEER_ADDR_CHANGE,
	                          SCTP_REMOTE_ERROR,
	                          SCTP_SHUTDOWN_EVENT,
	                          SCTP_ADAPTATION_INDICATION,
	                          SCTP_PARTIAL_DELIVERY_EVENT};
	unsigned int i;
	struct sctp_assoc_value av;
	const int on = 1;
	ssize_t n;
	int flags;
	socklen_t from_len;
	char buffer[BUFFER_SIZE];
	char name[INET6_ADDRSTRLEN];
	socklen_t infolen;
	struct sctp_rcvinfo rcv_info;
	unsigned int infotype;

	usrsctp_init(9899, NULL, debug_printf);

#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE);
#endif
	usrsctp_sysctl_set_sctp_blackhole(2);

	if ((sock = usrsctp_socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
	}
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (const void*)&on, (socklen_t)sizeof(int)) < 0) {
		perror("usrsctp_setsockopt SCTP_I_WANT_MAPPED_V4_ADDR");
	}
	memset(&av, 0, sizeof(struct sctp_assoc_value));
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 47;

	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_CONTEXT, (const void*)&av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("usrsctp_setsockopt SCTP_CONTEXT");
	}
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(int)) < 0) {
		perror("usrsctp_setsockopt SCTP_RECVRCVINFO");
	}

	memset(&encaps, 0, sizeof(struct sctp_udpencaps));
	encaps.sue_address.ss_family = AF_INET6;
	encaps.sue_port = htons(9889);
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
		perror("usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT");
	}

	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_FUTURE_ASSOC;
	event.se_on = 1;
	for (i = 0; i < (unsigned int)(sizeof(event_types)/sizeof(uint16_t)); i++) {
		event.se_type = event_types[i];
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(struct sctp_event)) < 0) {
			perror("usrsctp_setsockopt SCTP_EVENT");
		}
	}
	memset((void *)&addr, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SIN6_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(PORT);
	addr.sin6_addr = in6addr_any;
	if (usrsctp_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
		perror("usrsctp_bind");
	}
	if (usrsctp_listen(sock, 1) < 0) {
		perror("usrsctp_listen");
	}
	while (1) {

		from_len = (socklen_t)sizeof(struct sockaddr_in6);
		flags = 0;
		infolen = (socklen_t)sizeof(struct sctp_rcvinfo);
		n = usrsctp_recvv(sock, (void*)buffer, BUFFER_SIZE, (struct sockaddr *) &addr, &from_len, (void *)&rcv_info,
		                  &infolen, &infotype, &flags);
		if (n > 0) {
			if (flags & MSG_NOTIFICATION) {
				printf("Notification of length %llu received.\n", (unsigned long long)n);
			} else {
				if (infotype == SCTP_RECVV_RCVINFO) {
					printf("Msg of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u, complete %d.\n",
					        (unsigned long long)n,
					        inet_ntop(AF_INET6, &addr.sin6_addr, name, INET6_ADDRSTRLEN), ntohs(addr.sin6_port),
					        rcv_info.rcv_sid,
					        rcv_info.rcv_ssn,
					        rcv_info.rcv_tsn,
					        ntohl(rcv_info.rcv_ppid),
					        rcv_info.rcv_context,
					        (flags & MSG_EOR) ? 1 : 0);
					if (flags & MSG_EOR) {
						struct sctp_sndinfo snd_info;

						snd_info.snd_sid = rcv_info.rcv_sid;
						snd_info.snd_flags = 0;
						if (rcv_info.rcv_flags & SCTP_UNORDERED) {
							snd_info.snd_flags |= SCTP_UNORDERED;
						}
						snd_info.snd_ppid = rcv_info.rcv_ppid;
						snd_info.snd_context = 0;
						snd_info.snd_assoc_id = rcv_info.rcv_assoc_id;
						if (usrsctp_sendv(sock, response, (size_t)strlen(response), NULL, 0, &snd_info, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
							perror("sctp_sendv");
						}
					}
				} else {
					printf("Msg of length %llu received from %s:%u, complete %d.\n",
					        (unsigned long long)n,
					        inet_ntop(AF_INET6, &addr.sin6_addr, name, INET6_ADDRSTRLEN), ntohs(addr.sin6_port),
					        (flags & MSG_EOR) ? 1 : 0);
				}
			}
		} else {
			break;
		}

	}
	usrsctp_close(sock);
	while (usrsctp_finish() != 0) {
		sleep(SLEEP);
	}
	return (0);
}
