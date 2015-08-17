/*-
 * Copyright (c) 2011-2012 Felix Weinrank
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#ifndef _USER_NETMAP_H_
#define _USER_NETMAP_H_

#include <net/netmap_user.h>
#include <user_mbuf.h>

#if defined(MULTISTACK)
#include <net/multistack.h>
#endif // defined(MULTISTACK)

enum netmap_states {NETMAP_S_CLOSED, NETMAP_S_OPENING, NETMAP_S_OPEN, NETMAP_S_CLOSING};

struct sctp_netmap_base {
	enum netmap_states state;
	int fd;
	struct nmreq req;
	char *mem;
	struct netmap_if *iface;
#if defined(MULTISTACK)
    int ms_so;
    struct msreq ms_req;
	struct sockaddr_in ms_sin;
#endif /* defined(MULTISTACK) */
};



void usrsctp_netmap_ip_output(int *result, struct mbuf *o_pak);
void *usrsctp_netmap_recv_function(void *arg);
int usrsctp_netmap_init();
int usrsctp_netmap_close();

#endif
