/*
 * Copyright (C) 2017 Felix Weinrank
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
 * Usage: alt-hs-server [local_addr]
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
	struct socket *sock, *conn_sock;
	struct sockaddr_in addr;
	struct sctp_udpencaps encaps;
	ssize_t n;
	int flags;
	socklen_t from_len;
	char buffer[BUFFER_SIZE];
	socklen_t infolen;
	struct sctp_rcvinfo rcv_info;
	unsigned int infotype;
	socklen_t addr_len;
	struct sctp_sndinfo sndinfo;
	int optval;

	usrsctp_init(9899, NULL, debug_printf);
	usrsctp_sysctl_set_sctp_alternative_handshake(1);

#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_NONE);
#endif
	//usrsctp_sysctl_set_sctp_blackhole(2);

	if ((sock = usrsctp_socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
		perror("usrsctp_socket");
	}

	optval = 1;
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EMPTY_ALT_COOKIE, &optval, sizeof(int)) < 0) {
		perror("setsockopt: SCTP_EMPTY_ALT_COOKIE");
	}

	memset(&encaps, 0, sizeof(struct sctp_udpencaps));
	encaps.sue_address.ss_family 	= AF_INET6;
	encaps.sue_port 				= htons(9889);
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void*)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
		perror("usrsctp_setsockopt SCTP_REMOTE_UDP_ENCAPS_PORT");
	}

	memset((void *)&addr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
	addr.sin_len 			= sizeof(struct sockaddr_in);
#endif
	addr.sin_family 		= AF_INET;
	addr.sin_port 			= htons(PORT);
	addr.sin_addr.s_addr 	= htonl(INADDR_ANY);

	if (argc > 1) {
		if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
			perror("inet_pton");
			exit(EXIT_FAILURE);
		}
	}

	if (usrsctp_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
		perror("usrsctp_bind");
		exit(EXIT_FAILURE);
	}
	if (usrsctp_listen(sock, 1) < 0) {
		perror("usrsctp_listen");
		exit(EXIT_FAILURE);
	}

	memset(&sndinfo, 0, sizeof(sndinfo));

	while (1) {
		addr_len = 0;
		if ((conn_sock = usrsctp_accept(sock, NULL, &addr_len)) == NULL) {
			continue;
		}

		from_len = (socklen_t)sizeof(struct sockaddr_in6);
		flags = 0;
		infolen = (socklen_t)sizeof(struct sctp_rcvinfo);
		n = usrsctp_recvv(conn_sock, (void*)buffer, BUFFER_SIZE, (struct sockaddr *) &addr, &from_len, (void *)&rcv_info, &infolen, &infotype, &flags);
		if (n > 0) {
			if (usrsctp_sendv(conn_sock, response, strlen(response), NULL, 0, (void *)&sndinfo, (socklen_t)sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0) < 0) {
				perror("usrsctp_sendv");
				exit(EXIT_FAILURE);
			}
		}

		usrsctp_close(conn_sock);
	}

	while (usrsctp_finish() != 0) {
		sleep(SLEEP);
	}
	return (0);
}
