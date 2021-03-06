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

#include <assert.h>

//System V IPC
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

#ifndef ERR
	#define ERR 0
#endif

#define DEF_PF			//TODO
#define DEF_QN			//TODO

struct shared_memory {
	key_t shmkey;
	int shmid;
	void* shmseg;
};

int main ()
{
//Variables
u_int16_t pf;			//protocol family
u_uint16_t qn;			//the number of the queue
struct nfq_handle* nfq_handler;	//nfq handler
int fd;				//file descriptor
struct nfq_q_handle* queue_handler;	//queue handler
struct nfq_callback* cb;		//callback function
void* data;			//custom data to pass to the callback function
struct nfql_msg_packet_hdr* packet_header;
//Parsing
	parse_args();		//TODO

//Initialization
	pf = DEF_PF;
	qn = DEF_QN;
	cb = 			//TODO
	data = NULL;		//TODO
	
	nfq_handler = queuier_start_nfq(pf); //libnetfilter_queue installation
	assert(nfq_handler);
	queue_handler = nfq_create_queue(nfq_handler, qn, cb, data);
	if (!queue_handler) {
		fprintf(stderr, "an error occured during nfq_create_queue\n");
		return -ERR;
	}
	
	if (nfq_set_mode(queue_handler, NFQNL_COPY_META, 0xffff) < 0) {
//TODO NFQL_COPY_META
		fprintf(stderr, "can't set packet_copy mode\n");
		return -ERR;
	}
	
	//shared memory initialization
	shared_memory* shmem = malloc(sizeof(struct shared_memory), 1);
	shmem -> key_t = ftok(FILE_PATHNAME, PROJECT_ARG);
        shmem -> shmid = shnget(shmem -> shmkey, BUFFER_SIZE, IPC_CREAT);
        shmem -> smseg = shmat(shmem -> shmid, NULL, 0);

//Main body
	fd = nfq_fd(nfq_handler);
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		printf("pkt received\n");
		nfq_handle_packet(nfq_handler, buf, rv);
	}

				//TODO	shared memory closing?

	printf("unbinding from queue %d\n", qn);
	nfq_destroy_queue(queue_handler);

	printf("closing library handle\n");
	nfq_close(nfq_handler);
}

nfq_handle* queuier_start_nfq (u_int16_t pf)
{
	struct nfq_handle* handler;
	handler = nfq_open();
	if (!handler) {
		fprintf (stderr, "an error occured during hfq_open(). stopped.\n");
		return NULL;
	}

	if (nfq_unbind_pf(handler, pf) < 0) {
		fprintf(stderr, "an error occured dured nfq_unbind_pf()\n");
		return NULL;
	}

	if (nfq_bind_pf(handler, pf) < 0) {
		fprrintf(stderr, "an error occured during nfq_bind_pf()\n");
		return NULL;
	}

	return handler;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret;
        unsigned char *data;
 
        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
        	id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                         ntohs(ph->hw_protocol), ph->hook, id);
        }
 
        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);
 
                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                         printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }
 
        mark = nfq_get_nfmark(tb);
        if (mark)
        	printf("mark=%u ", mark);
 
        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);
 
        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);
 
        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);
 
        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
                printf("payload_len=%d ", ret);
 
        fputc('\n', stdout);
 
        return id;
}

static int cb (struct nfq_q_handler *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void* data)
{
	u_int32_t verdict = NF_DROP;
	u_int32_t id;
	int protocol;

	printf("entering callback\n");
	id = printk_pkt(nfa);
	protocol = queuier_get_packet_protocol();
	return nfq_set_verdict(qh, id, verdict, sizeof(int), &protocol);
}

#define FILE_PATHNAME		//TODO
#define PROJECT_ARG		//TODO
#define BUFFER_SIZE		//TODO
#define NUMBER_OF_SEMS		2
#define SEM_FREE_TO_USE		0
#define SIZE_SEMOPS_FREE_TO_USE	1
#define SEM_DATA_READY		1
#define SIZE_SEMOPS_DATA_READY	1
#define SEMGET_FLAGS		IPC_CREAT
#define SEMOPS_FLAGS		0
#define WAIT_FOR_ZERO		0
#define TAKE_THIS_SEM		-1
#define ONLY_ONE_SEMOP		1
static int queuier_get_packet_protocol (short unsigned int packet_checksum, const struct shared_memory* shrmem)
{
	if (!shrmem) {
		fprintf(stderr, "cant get acces to the shared memory segment -
			 				pointer is NULL");
		return -ERR;
	}
	//TODO set semaphore here
	int semid = semget(shrmem -> shmkey, NUMBER_OF_SEMS, SEMGET_FLAGS);
	if (semid < 0) {
		fprintf(stderr, "can't get semaphore 
					in queuier_get_packet_protocol()\n");
	
	int i;

	struct sembuf sops_ftu[SIZE_SEMOPS_FREE_TO_USE];/* = malloc(sizeof(sembuf), SIZE_SEMOPS_FREE_TO_USE); /*operations 
			to be performed on the SEM_FREE_TO_USE semaphore*/
	for (i=0; i<SIZE_SEMOPS_FREE_TO_USE; i++) {
		sops_ftu[i].sem_num = SEM_FREE_TO_USE;
	}
        //sops_ftu[0].sem_op = WAIT_FOR_ZERO; sops_ftu[0].sem_flg = NO_FLAGS;
	sops_ftu[0].sem_op = TAKE_THIS_SEM; sops_ftu[0].sem_flg = NO_FLAGS;

	struct sembuf sops_dr[SIZE_SEMOPS_DATA_READY];/* = malloc(sizeof(sembuf), SIZE_SEMOPS_DATA_READY); /*operations 
			to be performed on the SEM_DATA_READY semaphore*/
	for (i=0; i<SIZE_SEMOPS_DATA_READY; i++) {
		sops_dr[i].sem_num = SEM_DATA_READY;
	}
	sops_dr[0].sem_op = READ_PACKET; sops_dr[0].sem_flg = IPC_NOWAIT;
	
	//unsigned int nsops;
	int semop_ret;
	semop_ret = semop(semid, sops_ftu, SIZE_SEMOPS_FREE_TO_USE);
	if (semop_ret < 0) {
		fprintf(stderr, "can't wait until shared memory is free to use 
					in queuir_get_packet_protocol\n");
		return -ERR;
	}
	semop_ret = semop(semid, sops_dr, SIZE_SEMOPS_DATA_READY);
	if (semop_ret < 0) {
		fprintf(stderr, "can't read shared memory: nothing to read.
				I'll try one more time");
		union semun semval {0, NULL, NULL, NULL};
		semctl(semid, SEM_DATA_READY, SETVAL, semval);
		semop_ret = semop(semid, &sops_ftu[1], ONLY_ONE_OP);
		semop_ret = semop(semid, sops_dr, SIZE_SEMOPS_DATA_READY); 

	int ret = parser_get_packet_protocol_by_checksum(packet_checksum, shrmem);
	if (ret < 0) {
		fprintf(stderr, "can't get packet protocol 
					in queuier_get_packet_protocol()\n");
		return -ERR;
	}

	return ret;	
}
