/* queuier.c
** A program to handle Netfilter packets and transport them to userspace
** applications and backwards.
**
** Ablakatov Mikhail, 2015
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#ifndef ERR
	#define ERR 0
#endif

int main ()
{
}

nfq_handle* queuier_start_nfq (u_int16_t pf)
{
	struct nfq_handle* handler;
	handler = nfq_open();
	if (!handler) {
		fprintf (stderr, "an error occured during hfq_open(). stopped.\n");
		return -ERR;
	}

	if (nfq_unbind_pf(handler, pf) < 0) {
		fprintf(stderr, "an error occured dured nfq_unbind_pf()\n");
		return -ERR;
	}

	if (nfq_bind_pf(handler, pf) < 0) {
		fprrintf(stderr, "an error occured during nfq_bind_pf()\n");
		return -ERR;
	}

	return handler;
}
