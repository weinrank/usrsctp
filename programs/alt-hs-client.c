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
 * Usage: http_client remote_addr remote_port [local_port] [local_encaps_port] [remote_encaps_port] [uri]
 *
 * Example
 * Client: $ ./http_client 212.201.121.100 80 0 9899 9899 /cgi-bin/he
 */
#define BUFFER_SIZE 8096

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <usrsctp.h>
#include <sys/time.h>

#ifndef timersub
#define timersub(tvp, uvp, vvp)                                   \
	do {                                                      \
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;    \
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec; \
		if ((vvp)->tv_usec < 0) {                         \
			(vvp)->tv_sec--;                          \
			(vvp)->tv_usec += 1000000;                \
		}                                                 \
	} while (0)
#endif

int done = 0;
static const char *request = "GET / HTTP/1.0\r\nUser-agent: libusrsctp\r\nConnection: close\r\n\r\n";

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
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr;

	int result;
	char buffer[BUFFER_SIZE];
	struct sctp_udpencaps encaps;
	int n;
	socklen_t infolen;
	struct sctp_rcvinfo rcv_info;
	unsigned int infotype;
	int flags;
	socklen_t from_len;
	int loop_count;
	struct timeval time_start, time_now, time_diff;
	double seconds;
	uint8_t first_byte;

	result = 0;

	if (argc < 2) {
		printf("Not enough arguments!\n");
		exit(EXIT_FAILURE);
	}

	usrsctp_init(9889, NULL, debug_printf);
	usrsctp_sysctl_set_sctp_alternative_handshake(1);

#ifdef SCTP_DEBUG
	usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

	//usrsctp_sysctl_set_sctp_blackhole(2);

	seconds = 0.0;

	for (loop_count = 0; loop_count < 24; loop_count++) {
		if ((sock = usrsctp_socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL)) == NULL) {
			perror("usrsctp_socket");
			result = 1;
			goto out;
		}

		first_byte = 0;
		gettimeofday(&time_start, NULL);

		if (argc > 2) {
			memset((void *)&addr4, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
			addr4.sin_len 			= sizeof(struct sockaddr_in);
#endif
			addr4.sin_family 		= AF_INET;
			addr4.sin_port 			= htons(0);
			if (inet_pton(AF_INET, argv[2], &addr4.sin_addr) != 1) {
				perror("inet_pton");
				goto out;
			}
			if (usrsctp_bind(sock, (struct sockaddr *)&addr4, sizeof(struct sockaddr_in)) < 0) {
				perror("bind");
				goto out;
			}
		}

		memset(&encaps, 0, sizeof(struct sctp_udpencaps));
		encaps.sue_address.ss_family = AF_INET6;
		encaps.sue_port = htons(9899);
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, (const void *)&encaps, (socklen_t)sizeof(struct sctp_udpencaps)) < 0) {
			perror("setsockopt");
			usrsctp_close(sock);
			result = 3;
			goto out;
		}

		memset((void *)&addr4, 0, sizeof(struct sockaddr_in));
	#ifdef HAVE_SIN_LEN
		addr4.sin_len = sizeof(struct sockaddr_in);
	#endif

		addr4.sin_family   = AF_INET;
		addr4.sin_port     = htons(80);

		if (inet_pton(AF_INET, argv[1], &addr4.sin_addr) == 1) {
			if (usrsctp_connect(sock, (struct sockaddr *)&addr4, sizeof(struct sockaddr_in)) < 0) {
				perror("usrsctp_connect");
				usrsctp_close(sock);
				result = 5;
				goto out;
			}
		} else {
			printf("Illegal destination address\n");
			usrsctp_close(sock);
			result = 6;
			goto out;
		}

		/* send GET request */
		if (usrsctp_sendv(sock, request, strlen(request), NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0) < 0) {
			perror("usrsctp_sendv");
			usrsctp_close(sock);
			result = 6;
			goto out;
		}

		while (1) {
			from_len = (socklen_t)sizeof(struct sockaddr_in6);
			flags = 0;
			infolen = (socklen_t)sizeof(struct sctp_rcvinfo);
			n = usrsctp_recvv(sock, (void*)buffer, BUFFER_SIZE, (struct sockaddr *) &addr, &from_len, (void *)&rcv_info, &infolen, &infotype, &flags);

			if (n > 0 && first_byte == 0) {
				gettimeofday(&time_now, NULL);
				timersub(&time_now, &time_start, &time_diff);
				seconds += time_diff.tv_sec + (double)time_diff.tv_usec / 1000000.0;
				first_byte = 1;
			}

			//printf("received %d bytes\n", n);
			if (n < 0) {
				printf("something failed\n");
				exit(EXIT_FAILURE);
			}

			if (n == 0) {
				usrsctp_close(sock);
				break;
			}
		}
	}

	seconds = seconds / loop_count;

	printf("%f\n", seconds);

out:
	while (usrsctp_finish() != 0) {
		sleep(1);
	}
	return (result);
}
