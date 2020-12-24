/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "basicfwd.h"
#include "alt_header.h"
#include "packets.h"
#include "clover_structs.h"
#include <arpa/inet.h>

#include <rte_table.h>
#include <endian.h>


#define RC_SEND 0x04
#define RC_WRITE_ONLY 0x0A
#define RC_READ_REQUEST 0x0C
#define RC_READ_RESPONSE 0x10
#define RC_ACK 0x11
#define RC_ATOMIC_ACK 0x12
#define RC_CNS 0x13

#define RDMA_COUNTER_SIZE 256
#define RDMA_STRING_NAME_LEN 256
#define PACKET_SIZES 256

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 

#define MITSUME_PTR_MASK_LH 0x0ffffffff0000000
//#define MITSUME_PTR_MASK_OFFSET                 0x0000fffff8000000
#define MITSUME_PTR_MASK_NEXT_VERSION 0x0000000007f80000
#define MITSUME_PTR_MASK_ENTRY_VERSION 0x000000000007f800
#define MITSUME_PTR_MASK_XACT_AREA 0x00000000000007fe
#define MITSUME_PTR_MASK_OPTION 0x0000000000000001

#define MITSUME_GET_PTR_LH(A) (A & MITSUME_PTR_MASK_LH) >> 28


char ib_print[RDMA_COUNTER_SIZE][RDMA_STRING_NAME_LEN];

#define RDMA_CALL_SIZE 8192
static int rdma_counter = 0;
uint8_t rdma_calls[RDMA_CALL_SIZE];
uint32_t rdma_call_count[RDMA_COUNTER_SIZE];


static int packet_counter = 0;
uint64_t packet_size_index[RDMA_COUNTER_SIZE][PACKET_SIZES];
uint32_t packet_size_calls[RDMA_COUNTER_SIZE][PACKET_SIZES];

#define KEYSPACE 1000000
uint64_t read_req_addr_index[KEYSPACE];
uint32_t read_req_addr_count[KEYSPACE];

uint64_t read_resp_addr_index[KEYSPACE];
uint32_t read_resp_addr_count[KEYSPACE];

void count_values(uint64_t *index, uint32_t *count, uint32_t size, uint64_t value) {
	//search
	for (uint32_t i=0;i<size;i++) {
		if(index[i] == value) {
			count[i]++;
			return;
		}
	}
	//add new index
	for (uint32_t i=0;i<size;i++) {
		if(index[i] == 0) {
			index[i]=value;
			count[i]=1;
			return;
		}
	}
}

void print_count(uint64_t *index, uint32_t *count, uint32_t size) {
	for (uint32_t i=0;i<size;i++) {
		if (index[i] != 0) {
			printf("[%08d] Index: ",i);
			print_bytes((uint8_t *)&index[i],sizeof(uint64_t));
			printf(" Count: %d\n",count[i]);
		}
	}

}

void count_read_req_addr(struct read_request * rr) {
	count_values(read_req_addr_index,read_req_addr_count,KEYSPACE,rr->rdma_extended_header.vaddr);
}
/*
void count_read_resp_addr(struct read_response * rr) {
	count_values(read_resp_addr_index,read_resp_addr_count,KEYSPACE,rr->addr);
}*/

void print_read_req_addr(void) {
	print_count(read_req_addr_index,read_req_addr_count,KEYSPACE);
}
/*
void print_read_resp_addr(void) {
	print_count(read_resp_addr_index,read_resp_addr_count,KEYSPACE);
}
*/

void classify_packet_size(struct rte_ipv4_hdr *ip, struct roce_v2_header *roce) {
	uint32_t size = ntohs(ip->total_length);
	uint8_t opcode = roce->opcode;
	if (packet_counter == 0) {
		bzero(packet_size_index,RDMA_COUNTER_SIZE*PACKET_SIZES*sizeof(uint32_t));
		bzero(packet_size_calls,RDMA_COUNTER_SIZE*PACKET_SIZES*sizeof(uint32_t));
	}
	count_values(packet_size_index[opcode],packet_size_calls[opcode], PACKET_SIZES, size);
}



void print_bytes(const uint8_t * buf, uint32_t len) {
	for (uint32_t i=0;i<len;i++)  {
		printf("%02X ", buf[i]);
	}
}

void print_binary_bytes(const uint8_t * buf, uint32_t len) {
	for (uint32_t i=0;i<len;i++)  {
		printf(BYTE_TO_BINARY_PATTERN" ", BYTE_TO_BINARY(buf[i]));
	}
}

void print_address(uint64_t *address) {
	printf("address: ");
	print_bytes(address,sizeof(uint64_t));
	printf("\n");
}


void print_binary_address(uint64_t *address) {
	printf("bin address: ");
	print_binary_bytes(address,sizeof(uint64_t));
	printf("\n");
}

void print_ack_extended_header(struct AETH *aeth) {
	printf("Reserved        %u\n", ntohs(aeth->reserved));
	printf("Opcode          %u\n", ntohs(aeth->opcode));
	printf("Credit Count    %u\n", ntohs(aeth->credit_count));
	printf("Sequence Number %u\n", ntohl(aeth->sequence_number));
}

void print_rdma_extended_header(struct RTEH *rteh) {
	printf("virtual address: ");
	print_bytes((uint8_t *)&(rteh->vaddr),sizeof(uint64_t));
	printf("\n");

	printf("rkey: %u \traw:   ", ntohl(rteh->rkey));
	print_bytes((uint8_t *)&(rteh->rkey),sizeof(uint32_t));
	printf("\n");

	printf("dma len %u \traw: ", ntohl(rteh->dma_length));
	print_bytes((uint8_t *)&(rteh->dma_length),sizeof(uint32_t));
} 
 
void print_read_request(struct read_request* rr) {
	printf("(START) Read Request: \n");
	printf("(raw) ");
	print_bytes((void*) rr, 16);
	printf("\n");
	print_rdma_extended_header(&rr->rdma_extended_header);
	printf("\n");
	//printf("(STOP) Read Request\n");
	return;
}

void print_read_response(struct read_response *rr, uint32_t size) {
	printf("(START) Read Response (%d)\t",size);
	print_bytes((uint8_t*) rr, 10);
	printf("\n");
	//printf("(STOP) Read Response\n");
	return;
}

void print_write_request(struct write_request* wr) {
	printf("(START) Write Request\n");
	print_rdma_extended_header(&wr->rdma_extended_header);
	printf("(STOP) Write Request\n");
	return;
}


#define KEY_VERSION_RING_SIZE 256
static uint64_t key_address[KEYSPACE];
static uint64_t key_versions[KEYSPACE][KEY_VERSION_RING_SIZE];
static uint32_t key_count[KEYSPACE];


static int print_next = 0;
static uint64_t last_cns = 0;
static uint64_t last_write =0;

static uint64_t first_address=0;
static uint64_t first_cns=0;

static uint64_t second_address=0;
static uint64_t second_cns=0;
void true_classify(struct rte_mbuf * pkt) {
//void true_classify(struct rte_ipv4_hdr *ip, struct roce_v2_header *roce, struct clover_hdr * clover) {
	struct rte_ether_hdr * eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct rte_ipv4_hdr* ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr * udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
	struct roce_v2_header * roce_hdr = (struct roce_v2_header *)((uint8_t*)udp_hdr + sizeof(struct rte_udp_hdr));
	struct clover_hdr * clover_header = (struct clover_hdr *)((uint8_t *)roce_hdr + sizeof(roce_v2_header));

	uint32_t size = ntohs(ipv4_hdr->total_length);
	uint8_t opcode = roce_hdr->opcode;


	if (size == 60 && opcode == RC_READ_REQUEST) {
		struct read_request * rr = (struct read_request *)clover_header;
		//print_packet(pkt);
		//print_read_request(rr);
		count_read_req_addr(rr);
	}


	//if (size == 1072 && opcode == RC_READ_RESPONSE) {
	if ((size == 56 || size == 1072) && opcode == RC_READ_RESPONSE) {
		struct read_response * rr = (struct read_response*) clover_header;

		//print_packet(pkt);
		//print_read_response(rr, size);
		//count_read_resp_addr(rr);
	}

	if (size == 1084 && opcode == RC_WRITE_ONLY) {
	//if (opcode == RC_WRITE_ONLY) {
		//printf("write request\n");
		//This is a data write
		struct write_request * wr = (struct write_request*) clover_header;
		uint64_t *key = &(wr->data);

		//only print key 1
		if (key[0] == 1) {
			print_next = 1;
			uint64_t address = wr->rdma_extended_header.vaddr;

			if(first_address != 0 && second_address == 0) {
				second_address = be64toh(wr->rdma_extended_header.vaddr);
			}

			if(first_address==0) {
				first_address = wr->rdma_extended_header.vaddr;
			}


			if (last_write !=0 && first_cns != 0) {
				printf("first address ");
				print_address(&first_address);
				print_binary_address(&first_address);

				printf("first cns ");
				print_address(&first_cns);
				print_binary_address(&first_cns);

				/*
				uint64_t predict_address = ((be64toh(wr->rdma_extended_header.vaddr) - first_address) >> 10) + first_cns;
				printf("predict from not ");
				predict_address = htobe64(predict_address);
				print_address(&predict_address);
				print_binary_address(&predict_address);
				*/

				printf("predict from not v2 ");
				//uint64_t predict_address = ((be64toh(wr->rdma_extended_header.vaddr) - be64toh(first_address)) >> 10) + be64toh(second_cns);
				uint64_t predict_address = ((be64toh(wr->rdma_extended_header.vaddr) - be64toh(first_address)) >> 10) + second_cns;
				predict_address = htobe64(predict_address);
				print_address(&predict_address);
				print_binary_address(&predict_address);


			}

			if (last_write !=0 && second_cns != 0) {
				printf("second address ");
				uint64_t tmp_second_address = htobe64(second_address);
				print_address(&tmp_second_address);
				print_binary_address(&tmp_second_address);

				printf("second cns ");
				uint64_t tmp_second_cns = htobe64(second_cns);
				print_address(&tmp_second_cns);
				print_binary_address(&tmp_second_cns);


				uint64_t predict_address = ((be64toh(wr->rdma_extended_header.vaddr) - second_address) >> 10) + second_cns;
				printf("predict from not 2");
				predict_address = htobe64(predict_address);
				print_address(&predict_address);
				print_binary_address(&predict_address);
			}
			//print_packet(pkt);

			//printf("--------------write-------------\n");
			//printf("write ");
			//print_address(&address);

			//printf("next pointer: ");
			//print_address(&wr->ptr);
			//printf("\n");

			if (last_write != 0) {
				uint64_t diff = be64toh(wr->rdma_extended_header.vaddr) - be64toh(last_write);
				diff = htobe64(diff);
				printf("last write diff ");
				print_address(&diff);
				print_binary_address(&diff);

				//uint64_t predict_diff = diff >> 10;
				printf("predict diff ");
				uint64_t predict_diff = be64toh(diff) >> 10;
				predict_diff = htobe64(predict_diff);
				print_address(&predict_diff);
				print_binary_address(&predict_diff);

				printf("predict address ");
				uint64_t predict_address = ((be64toh(wr->rdma_extended_header.vaddr) - be64toh(last_write)) >> 10) + be64toh(last_cns);
				predict_address = htobe64(predict_address);
				print_address(&predict_address);
				print_binary_address(&predict_address);
			}
			last_write = wr->rdma_extended_header.vaddr;

			if (size >= 1084) {
				//printf("key %02X %02X %02X %02X \n",key[0], key[1], key[2], key[3]);
				//Update current write kv location
				key_address[*key] = wr->rdma_extended_header.vaddr;
				//Update the most recent version of the kv store
				key_versions[*key][key_count[*key]%KEY_VERSION_RING_SIZE]=wr->rdma_extended_header.vaddr;
				//update the keys write count
				key_count[*key]++;
			} else {
				printf("size too small to print extra data\n");
			}
			//printf("--------------//write-------------\n");
		}



		//Periodically print the sate of a particular key.
		if (*key == 1 && key_count[*key]==KEY_VERSION_RING_SIZE) {
			for (int i=0;i<KEY_VERSION_RING_SIZE;i++){
				printf("key: %d address:%"PRIu64" index: %d\n",*key,key_versions[*key][i], i+(key_count[*key]-KEY_VERSION_RING_SIZE));
			}
		}

		//TODO this is where a check and set operation for a given key should be generated
	}

	//if (size == 72 && opcode == RC_CNS) {
	if (size == 72 && opcode == RC_CNS && print_next) {
		//print_packet(pkt);
		print_next = 0;
		struct cs_request * cs = (struct cs_request*) clover_header;

		//printf("-----------CNS---------------------\n");
		//printf("vaddr ");
		//print_address(&(cs->atomic_req.vaddr));

		//((uint8_t*)(&cs->atomic_req.compare))[1] = 0x00;
		//((uint8_t*)(&cs->atomic_req.compare))[2] = 0x07;
		//((uint8_t*)(&cs->atomic_req.compare))[5] = 0x00;

		//printf("compare ");
		//print_address(&(cs->atomic_req.compare));
		printf("swap_or_add ");
		uint64_t swap = MITSUME_GET_PTR_LH(be64toh(cs->atomic_req.swap_or_add));
		swap = htobe64(swap);
		print_address(&swap);
		print_binary_address(&swap);
		//printf("--o-- swap_or_add ");
		//uint64_t oswap = cs->atomic_req.swap_or_add;
		//print_address(&oswap);
		//print_binary_address(&oswap);


		if(second_cns==0 && first_cns!=0) {
			second_cns = MITSUME_GET_PTR_LH(be64toh(cs->atomic_req.swap_or_add));
			first_cns = htobe64(MITSUME_GET_PTR_LH(be64toh(cs->atomic_req.swap_or_add)));
		}

		if(first_cns==0) {
			first_cns = htobe64(MITSUME_GET_PTR_LH(be64toh(cs->atomic_req.swap_or_add)));
		}


		if (last_cns != 0) {
			printf("cns gap        ");
			uint64_t diff = be64toh(swap) - be64toh(last_cns);
			diff = htobe64(diff);
			print_address(&diff);
			print_binary_address(&diff);

		}
		last_cns = swap;
		printf("\n");
		//printf("rkey %d \n",&(cs->atomic_req.rkey));
		//printf("-----------//CNS---------------------\n");
	}

	if (packet_counter % 10000 == 0) {
		//print_read_req_addr();
		//print_read_resp_addr();

		for (int i=0;i<KEYSPACE;i++) {
			if (key_address[i] != 0) {
				///printf("key %i: address: %"PRIu64": writes: %d\n",i,key_address[i],key_count[i]);
			}
		}
	}
	return;
}


void print_classify_packet_size(void) {
	for (int i=0;i<RDMA_COUNTER_SIZE;i++) {
		for (int j=0;j<PACKET_SIZES;j++) {
			if(packet_size_index[i][j] != 0)
				printf("Call: %s Size: %"PRIu64", calls: %d\n",ib_print[i],packet_size_index[i][j],packet_size_calls[i][j]);
		}
	}
	printf("----------------------------\n");
}


void rdma_count_calls(roce_v2_header *rdma) {
	rdma_call_count[rdma->opcode]++;
	return;
}


void print_rdma_call_count(void) {
	if (rdma_counter % 100 == 0) {
		for (int i=0;i<RDMA_COUNTER_SIZE;i++) {
			if (rdma_call_count[i] > 0) {
				printf("Call: %s Count: %d Raw: %02X\n",ib_print[i],rdma_call_count[i],i);
			}
		}

	}
	return;
}

//TODO remove this function, it's rather useless
void rdma_print_pattern(roce_v2_header * rdma) {
	if (likely(rdma_counter < RDMA_CALL_SIZE)) {
		rdma_calls[rdma_counter]=rdma->opcode;
	} else {
		#define LINE_LEN 10
		uint32_t t=0;
		for (int i=0;i<RDMA_CALL_SIZE;i+=LINE_LEN) {
			for (int j=0;j<LINE_LEN && t < RDMA_CALL_SIZE;j++) {
				switch(rdma_calls[t]){
					case RC_SEND: 
						printf("m");
						break;
					case RC_WRITE_ONLY: 
						printf("W");
						break;
					case RC_ACK: break;
						break;
					default:
						break;
				}
				t++;
			}
			printf("\n");
		}
		exit(0);
	}
	return;
}



//ib_print[RC_ACK] = "RC_ACK\0";
void init_ib_words(void) {
	strcpy(ib_print[RC_SEND],"RC_SEND");
	strcpy(ib_print[RC_WRITE_ONLY],"RC_WRITE_ONLY");
	strcpy(ib_print[RC_READ_REQUEST],"RC_READ_REQUEST");
	strcpy(ib_print[RC_READ_RESPONSE],"RC_READ_RESPONSE");
	strcpy(ib_print[RC_ACK],"RC_ACK");
	strcpy(ib_print[RC_ATOMIC_ACK],"RC_ATOMIC_ACK");
	strcpy(ib_print[RC_CNS],"RC_COMPARE_AND_SWAP");
}


int log_printf(int level, const char *format, ...) {
	va_list args;
    va_start(args, format);
	int ret = 0;
	if (LOG_LEVEL >= level) {
		ret = vprintf(format,args);
	}
	va_end(args);
	return ret;
}

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

void print_raw(struct rte_mbuf* pkt){
	printf("\n\n\n\n----(start-raw) (new packet)\n\n");
	int room = rte_pktmbuf_headroom(pkt);
	for (int i=rte_pktmbuf_headroom(pkt);(uint16_t)i<(pkt->data_len + rte_pktmbuf_headroom(pkt));i++){
		printf("%02X ",(uint8_t)((char *)(pkt->buf_addr))[i]);
		if (i - room == sizeof(struct rte_ether_hdr) - 1) { // eth
			printf("|\n");
		}
		if (i - room == sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) - 1) { // eth
			printf("|\n");
		}
		if (i  - room == sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) - 1) { // eth
			printf("|\n");
		}
		if (i  - room == sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct roce_v2_header) - 1) { // eth
			printf("|\n");
		}
		if (i  - room == sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct roce_v2_header) + sizeof(struct mitsume_msg_header) -1 ) {
			printf("|\n");
		}
		//printf("%c-",((char *)pkt->userdata)[itter]);
	}
	printf("\n----(end-raw)----\n");
}

void print_ether_hdr(struct rte_ether_hdr * eth){
	// L2 headers
	struct rte_ether_addr src_macaddr;
	struct rte_ether_addr dst_macaddr;	

	src_macaddr = eth->s_addr;
	dst_macaddr = eth->d_addr;
	printf("src_macaddr: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		src_macaddr.addr_bytes[0], src_macaddr.addr_bytes[1],
		src_macaddr.addr_bytes[2], src_macaddr.addr_bytes[3],
		src_macaddr.addr_bytes[4], src_macaddr.addr_bytes[5]);

	printf("dst_macaddr: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		dst_macaddr.addr_bytes[0], dst_macaddr.addr_bytes[1],
		dst_macaddr.addr_bytes[2], dst_macaddr.addr_bytes[3],
		dst_macaddr.addr_bytes[4], dst_macaddr.addr_bytes[5]);

	return;
}

struct rte_ether_hdr *eth_hdr_process(struct rte_mbuf* buf) {
	struct rte_ether_hdr * eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);

	if(eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)){									

		#ifdef TURN_PACKET_AROUND
		//Swap ethernet addresses
		struct rte_ether_addr temp_eth_addr   = eth_hdr->s_addr;
		eth_hdr->s_addr = eth_hdr->d_addr;
		eth_hdr->d_addr = temp_eth_addr;
		#endif

		#ifdef PACKET_DEBUG_PRINTOUT

		print_ether_hdr(eth_hdr);
		print_raw(buf);

		#endif
		return eth_hdr;
	}
	return NULL;
}

void print_ip_hdr(struct rte_ipv4_hdr * ipv4_hdr) {
	// L3 headers: IPv4
	uint32_t dst_ipaddr;
	uint32_t src_ipaddr;

	src_ipaddr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	dst_ipaddr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	uint8_t src_addr[4];
	src_addr[0] = (uint8_t) (src_ipaddr >> 24) & 0xff;
	src_addr[1] = (uint8_t) (src_ipaddr >> 16) & 0xff;
	src_addr[2] = (uint8_t) (src_ipaddr >> 8) & 0xff;
	src_addr[3] = (uint8_t) src_ipaddr & 0xff;
	printf("src_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", 
			src_addr[0], src_addr[1], src_addr[2], src_addr[3]);

	uint8_t dst_addr[4];
	dst_addr[0] = (uint8_t) (dst_ipaddr >> 24) & 0xff;
	dst_addr[1] = (uint8_t) (dst_ipaddr >> 16) & 0xff;
	dst_addr[2] = (uint8_t) (dst_ipaddr >> 8) & 0xff;
	dst_addr[3] = (uint8_t) dst_ipaddr & 0xff;
	printf("dst_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", 
		dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
	return;

}

struct rte_ipv4_hdr* ipv4_hdr_process(struct rte_ether_hdr *eth_hdr) {

	struct rte_ipv4_hdr* ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr));
	int hdr_len = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

	if (hdr_len == sizeof(struct rte_ipv4_hdr)) {

		#ifdef TURN_PACKET_AROUND
		//Swap ipv4 addr
		uint32_t temp_ipv4_addr = ipv4_hdr->src_addr;
		ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
		ipv4_hdr->dst_addr = temp_ipv4_addr;
		#endif
		
		#ifdef PACKET_DEBUG_PRINTOUT
		print_ipv4_hdr(ipv4_hdr);
		#endif		

		return ipv4_hdr;
	}
	return NULL;
}

void print_udp_hdr(struct rte_udp_hdr * udp_hdr) {
	// L4 headers: UDP 
	uint16_t dst_port = 0;
	uint16_t src_port = 0;
	dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
	src_port = rte_be_to_cpu_16(udp_hdr->src_port);
	//Because of the way we fill in these data, we don't need rte_be_to_cpu_32 or rte_be_to_cpu_16 
	printf("src_port:%" PRIu16 ", dst_port:%" PRIu16 "\n", src_port, dst_port);
	printf("-------------------\n");
	return;

}

struct rte_udp_hdr * udp_hdr_process(struct rte_ipv4_hdr *ipv4_hdr) {

	//ipv4_udp_rx++;
	//log_printf(INFO,"ipv4_udp_rx:%" PRIu16 "\n",ipv4_udp_rx);

	struct rte_udp_hdr * udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
	if (ipv4_hdr->next_proto_id == IPPROTO_UDP){

		#ifdef TURN_PACKET_AROUND
		//Swap udp ports
		uint16_t temp_udp_port = udp_hdr->src_port;
		udp_hdr->src_port = udp_hdr->dst_port; 
		udp_hdr->dst_port = temp_udp_port;							
		udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct alt_header) + sizeof(struct rte_udp_hdr));
		//alt = (struct alt_header *)((uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr));
		#endif

		#ifdef PACKET_DEBUG_PRINTOUT
		print_udp_hdr(udp_hdr);
		#endif

		//udp_hdr->dgram_cksum = 0;									
		//udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, (void*)udp_hdr);

		return udp_hdr;
	}
	return NULL;
}

void print_roce_v2_hdr(roce_v2_header * rh) {
    printf("op code             %02X %s\n",rh->opcode, ib_print[rh->opcode]);
    printf("solicited event     %01X\n",rh->solicited_event);
    printf("migration request   %01X\n",rh->migration_request);
    printf("pad count           %01X\n",rh->pad_count);
    printf("transport version   %01X\n",rh->transport_header_version);
    printf("partition key       %02X\n",rh->partition_key);
    printf("fecn                %01X\n",rh->fecn);
    printf("becn                %01X\n",rh->bcen);
    printf("reserved            %01X\n",rh->reserved);
    printf("dest qp             %02X\n",rh->dest_qp);
    printf("ack                 %01X\n",rh->ack);
    printf("reserved            %01X\n",rh->reserved);
    printf("packet sequence #   %02X\n",rh->packet_sequence_number);
    //printf("padding             %02X\n",rh->padding);
    //printf("ICRC                %01X\n",rh->ICRC);
}

struct roce_v2_header * roce_hdr_process(struct rte_udp_hdr * udp_hdr) {
	//Dont start parsing if the udp port is not roce
	struct roce_v2_header * roce_hdr = NULL;
	if (likely(rte_be_to_cpu_16(udp_hdr->dst_port) == ROCE_PORT)) {
		roce_hdr = (struct roce_v2_header *)((uint8_t*)udp_hdr + sizeof(struct rte_udp_hdr));

		rdma_counter++;

		#ifdef PACKET_DEBUG_PRINTOUT
		print_roce_v2_header(roce_hdr);
		#endif

		//rdma_count(roce_hdr);
		//rdma_count_calls(roce_hdr);
		//print_rdma_call_count();

		return roce_hdr;
	}
	return NULL;
}

void print_clover_hdr(struct clover_hdr * clover_header) {
		printf("-----------------------------------------\n");
		printf("size of rocev2 header = %ld\n",sizeof(struct roce_v2_header));
		printf("CLOVER MESSAGE TIME\n");

		printf("((potential first 8 byte addr ");
		print_bytes((uint8_t *)&clover_header->ptr.pointer, sizeof(uint64_t));
		printf("\n");

		struct mitsume_msg * clover_msg;
		clover_msg = &(clover_header->mitsume_hdr);
		struct mitsume_msg_header *header = &(clover_msg->msg_header);

		printf("msg-type  %d ntohl %d\n",header->type,ntohl(header->type));
		printf("source id %d ntohl %d\n",header->src_id,ntohl(header->src_id));
		printf("dest id %d ntohl %d\n",header->des_id,ntohl(header->des_id));
		printf("thread id %d ntohl %d \n",header->thread_id, ntohl(header->thread_id));

		printf("(ib_mr_attr) -- Addr");
		print_bytes((uint8_t *) &header->reply_attr.addr, sizeof(uint64_t));
		printf("\n");

		printf("(ib_mr_attr) -- rkey %d\n",ntohl(header->reply_attr.rkey));
		printf("(ib_mr_attr) -- mac id %d\n",ntohs(header->reply_attr.machine_id));

}

struct clover_hdr * mitsume_msg_process(struct roce_v2_header * roce_hdr){

	struct clover_hdr * clover_header = (struct clover_hdr *)((uint8_t *)roce_hdr + sizeof(roce_v2_header));

	#ifdef PACKET_DEBUG_PRINTOUT
	print_clover_header(clover_hdr);
	#endif 

	return clover_header;
}

void print_packet(struct rte_mbuf * buf) {
	struct rte_ether_hdr * eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	struct rte_ipv4_hdr* ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr * udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
	struct roce_v2_header * roce_hdr = (struct roce_v2_header *)((uint8_t*)udp_hdr + sizeof(struct rte_udp_hdr));
	struct clover_hdr * clover_header = (struct clover_hdr *)((uint8_t *)roce_hdr + sizeof(roce_v2_header));
	print_raw(buf);
	print_ether_hdr(eth_hdr);
	print_ip_hdr(ipv4_hdr);
	print_udp_hdr(udp_hdr);
	print_roce_v2_hdr(roce_hdr);
	//print_clover_hdr(clover_header);

}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;	

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			log_printf(INFO,"WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	log_printf(INFO,"\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	struct rte_ether_hdr* eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr; 
	struct rte_udp_hdr* udp_hdr;
	struct roce_v2_header * roce_hdr;
	struct clover_hdr * clover_header;
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {
			uint16_t ipv4_udp_rx = 0;	

			/* Get burst of RX packets, from first and only port */
			struct rte_mbuf *rx_pkts[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0, rx_pkts, BURST_SIZE);
		
			if (unlikely(nb_rx == 0))
				continue;

			log_printf(INFO,"rx:%" PRIu16 "\n",nb_rx);			

			for (uint16_t i = 0; i < nb_rx; i++){
				

				#ifdef PACKET_DEBUG_PRINTOUT	
				#endif

				packet_counter++;

				eth_hdr = eth_hdr_process(rx_pkts[i]);
				if (unlikely(eth_hdr == NULL)) {
					log_printf(DEBUG, "ether header not the correct format dropping packet\n");
					rte_pktmbuf_free(rx_pkts[i]);
					continue;
				}

				ipv4_hdr = ipv4_hdr_process(eth_hdr);
				if (unlikely(ipv4_hdr == NULL)) {
					log_printf(DEBUG, "ipv4 header not the correct format dropping packet\n");
					rte_pktmbuf_free(rx_pkts[i]);
					continue;
				}
				udp_hdr = udp_hdr_process(ipv4_hdr);

				if (unlikely(udp_hdr == NULL)) {
					log_printf(DEBUG, "udp header not the correct format dropping packet\n");
					rte_pktmbuf_free(rx_pkts[i]);
					continue;
				}

				roce_hdr = roce_hdr_process(udp_hdr);
				if (unlikely(roce_hdr == NULL)) {
					log_printf(DEBUG, "roceV2 header not correct dropping packet\n");
					rte_pktmbuf_free(rx_pkts[i]);
					continue;
				}

				clover_header = mitsume_msg_process(roce_hdr);
				if (unlikely(clover_header == NULL)) {
					log_printf(DEBUG, "clover msg not parsable for some reason\n");
					rte_pktmbuf_free(rx_pkts[i]);
					continue;
				}

				classify_packet_size(ipv4_hdr,roce_hdr);
				if (packet_counter % 1000000 == 0) {
					print_classify_packet_size();
				}



				true_classify(rx_pkts[i]);

				//this must be recomputed if the packet is changed
				//ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
				//rte_pktmbuf_free(rx_pkts[i]);
			}							
			log_printf(INFO,"rx:%" PRIu16 ",udp_rx:%" PRIu16 "\n",nb_rx, ipv4_udp_rx);	

			/* Send burst of TX packets, to the same port */
			const uint16_t nb_tx = rte_eth_tx_burst(port, 0, rx_pkts, nb_rx);
			//printf("rx:%" PRIu16 ",tx:%" PRIu16 ",udp_rx:%" PRIu16 "\n",nb_rx, nb_tx, ipv4_udp_rx);
			//printf("rx:%" PRIu16 ",tx:%" PRIu16 "\n",nb_rx, nb_tx);

			/* Free any unsent packets. */
			 if (unlikely(nb_tx < nb_rx)) {
				log_printf(DEBUG, "Freeing packets that were not sent %d",nb_rx - nb_tx);
			 	uint16_t buf;
			 	for (buf = nb_tx; buf < nb_rx; buf++)
			 		rte_pktmbuf_free(rx_pkts[buf]);
			 }
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	printf("num ports:%u\n", nb_ports);
	//if (nb_ports < 2 || (nb_ports & 1))
	//	rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	printf("Running on #%d cores\n",rte_lcore_count());


	init_ib_words();
	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
