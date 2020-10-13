/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2014-2020 Mellanox Technologies, Ltd
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_flow.h>

#include "macswap_common.h"
#include "testpmd.h"
#include "alt_header.h"

//ST: for packet/request redirection
#define REDIRECT_ENABLED 1
//#define REDIRECT_DEBUG_PRINT 1
#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

struct rte_ether_hdr *ether_header;
struct rte_ipv4_hdr *ipv4_header;
struct rte_udp_hdr *udp_header;
int passthrough_counter = 0; 

static inline int
min_load(uint64_t x, uint64_t y, uint64_t z){
  return x < y ? (x < z ? 1 : 3) : (y < z ? 2 : 3);
}

static inline void
swap_mac(struct rte_ether_hdr *eth_hdr)
{
	struct rte_ether_addr addr;

	#ifdef REDIRECT_DEBUG_PRINT
	struct rte_ether_addr src_macaddr = eth_hdr->s_addr;
	struct rte_ether_addr dst_macaddr = eth_hdr->d_addr;
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
	#endif

	/* Swap dest and src mac addresses. */
	rte_ether_addr_copy(&eth_hdr->d_addr, &addr);
	rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
	rte_ether_addr_copy(&addr, &eth_hdr->s_addr);
}

static inline void
swap_ipv4(struct rte_ipv4_hdr *ipv4_hdr)
{
	rte_be32_t addr;

	#ifdef REDIRECT_DEBUG_PRINT
	uint32_t src_ipaddr = rte_be_to_cpu_32(ipv4_hdr->src_addr);
	uint32_t dst_ipaddr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
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
	#endif	

	/* Swap dest and src ipv4 addresses. */
	addr = ipv4_hdr->src_addr;
	ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
	ipv4_hdr->dst_addr = addr;
}

static inline void
swap_ipv6(struct rte_ipv6_hdr *ipv6_hdr)
{
	uint8_t addr[16];

	/* Swap dest and src ipv6 addresses. */
	memcpy(&addr, &ipv6_hdr->src_addr, 16);
	memcpy(&ipv6_hdr->src_addr, &ipv6_hdr->dst_addr, 16);
	memcpy(&ipv6_hdr->dst_addr, &addr, 16);
}

static inline void
swap_tcp(struct rte_tcp_hdr *tcp_hdr)
{
	rte_be16_t port;

	/* Swap dest and src tcp port. */
	port = tcp_hdr->src_port;
	tcp_hdr->src_port = tcp_hdr->dst_port;
	tcp_hdr->dst_port = port;
}

static inline void
swap_udp(struct rte_udp_hdr *udp_hdr)
{
	rte_be16_t port;

	/* Swap dest and src udp port */
	port = udp_hdr->src_port;
	udp_hdr->src_port = udp_hdr->dst_port;
	udp_hdr->dst_port = port;
}

/*
 * 5 tuple swap forwarding mode: Swap the source and the destination of layers
 * 2,3,4. Swaps source and destination for MAC, IPv4/IPv6, UDP/TCP.
 * Parses each layer and swaps it. When the next layer doesn't match it stops.
 */
static void
pkt_burst_5tuple_swap(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct rte_port  *txp;
	struct rte_mbuf *mb;
	uint16_t next_proto;
	uint64_t ol_flags;
	uint16_t proto;
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;

	int i;
	void* lookup_result;
	struct table_key ip_service_key;
	rte_be32_t ip_mac_key;
	int drop_index_list[128];
	int drop_index = 0;

	struct timespec ts1, ts2;

	union {
		struct rte_ether_hdr *eth;
		struct rte_vlan_hdr *vlan;
		struct rte_ipv4_hdr *ipv4;
		struct rte_ipv6_hdr *ipv6;
		struct rte_tcp_hdr *tcp;
		struct rte_udp_hdr *udp;
		struct alt_header *alt;
		uint8_t *byte;
	} h;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	clock_gettime(CLOCK_REALTIME, &ts1);

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif

	fs->rx_packets += nb_rx;
	txp = &ports[fs->tx_port];
	ol_flags = ol_flags_init(txp->dev_conf.txmode.offloads);
	vlan_qinq_set(pkts_burst, nb_rx, ol_flags,
			txp->tx_vlan_id, txp->tx_vlan_id_outer);
	for (i = 0; i < nb_rx; i++) {
		if (likely(i < nb_rx - 1))
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i+1],
					void *));
		mb = pkts_burst[i];
		h.eth = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
		ether_header = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
		//printf("eth_hdr:%p\n", (void *) ether_header);
		proto = h.eth->ether_type;
		swap_mac(h.eth);
		mb->l2_len = sizeof(struct rte_ether_hdr);
		h.eth++;

		// Presumably we don't have VLAN setup on AWS?
		while (proto == RTE_BE16(RTE_ETHER_TYPE_VLAN) ||
		       proto == RTE_BE16(RTE_ETHER_TYPE_QINQ)) {
			proto = h.vlan->eth_proto;
			h.vlan++;
			mb->l2_len += sizeof(struct rte_vlan_hdr);
		}

		if (proto == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
			ipv4_header = h.ipv4;
			//printf("ipv4_hdr:%p\n", (void *) ipv4_header);			
			swap_ipv4(h.ipv4);
			next_proto = h.ipv4->next_proto_id;
			mb->l3_len = (h.ipv4->version_ihl & 0x0f) * 4;
			h.byte += mb->l3_len;
		} else if (proto == RTE_BE16(RTE_ETHER_TYPE_IPV6)) {
			swap_ipv6(h.ipv6);
			next_proto = h.ipv6->proto;
			h.ipv6++;
			mb->l3_len = sizeof(struct rte_ipv6_hdr);
		} else {
			mbuf_field_set(mb, ol_flags);
			continue;
		}

		if (next_proto == IPPROTO_UDP) {
			udp_header = h.udp;
			//printf("h.udp:%p\n", (void *) h.udp);
			swap_udp(h.udp);	
			mb->l4_len = sizeof(struct rte_udp_hdr);
			h.byte += mb->l4_len;
			#ifdef REDIRECT_ENABLED
			// the whole if section is working with fixed redirection
			uint8_t type = get_alt_header_msgtype(h.alt);
			//printf("alt_header type:%" PRIu8 "\n", type);
			if( get_alt_header_msgtype(h.alt) == SINGLE_PKT_REQ){ 				
				//|| (alt_header_msgtype(h.alt) == MULTI_PKT_REQ && alt_header_isfirst(h.alt) == 1) ){							
				//redirecting packets!				
				#ifdef REDIRECT_DEBUG_PRINT 
				printf("pkt service_id: %" PRIu16 "\n", h.alt->service_id);
				printf("pkt type: %" PRIu8 "\n", get_alt_header_msgtype(h.alt));
				#endif
				uint64_t load1 = 0, load2 = 0, load3 = 0;
				ip_service_key.service_id = h.alt->service_id;

				// look up load based on service id and dst ip addr 1 to 3.
				// TODO: OPT Use bulk lookup?
				ip_service_key.ip_dst = h.alt->alt_dst_ip;
				int ret = rte_hash_lookup_data(fs->ip2load_table, (void*) &ip_service_key, &lookup_result);
				if(ret >= 0){
					uint64_t* ptr = (uint64_t*) lookup_result;
					load1 = *ptr; 
				}
				else{
					load1 = UINT64_MAX;
				}	

				ip_service_key.ip_dst = h.alt->alt_dst_ip2;
				ret = rte_hash_lookup_data(fs->ip2load_table, (void*) &ip_service_key, &lookup_result);
				if(ret >= 0){
					uint64_t* ptr = (uint64_t*) lookup_result;
					load2 = *ptr; 
				}
				else{
					load2 = UINT64_MAX;
				}				

				ip_service_key.ip_dst = h.alt->alt_dst_ip3;
				ret = rte_hash_lookup_data(fs->ip2load_table, (void*) &ip_service_key, &lookup_result);
				if(ret >= 0){
					uint64_t* ptr = (uint64_t*) lookup_result;
					load3 = *ptr; 
				}
				else{
					load3 = UINT64_MAX;
				}	

				// look up src mac addr for our ip src addr				
				// ret = rte_hash_lookup_data(fs->ip2mac_table, (void*) &ipv4_header->src_addr, &lookup_result);
				// if(ret >= 0){
				// 	struct rte_ether_addr* lookup1 = (struct rte_ether_addr*)(uintptr_t) lookup_result;
				// 	#ifdef REDIRECT_DEBUG_PRINT 
				// 	printf("eth_addr lookup: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
				// 		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
				// 	lookup1->addr_bytes[0], lookup1->addr_bytes[1],
				// 	lookup1->addr_bytes[2], lookup1->addr_bytes[3],
				// 	lookup1->addr_bytes[4], lookup1->addr_bytes[5]);
				// 	#endif
				// }
				// else{
				// 	if (errno == ENOENT)
				// 		printf("value not found\n");
				// 	else
				// 		printf("invalid parameters\n");
				// }

				// a potential problem here: what if we don't get all three values?
				// -> we set missing values to UINT64_MAX, so it's unlikely they'll get selected.
				int min_index = min_load(load1,load2,load3);
				#ifdef REDIRECT_DEBUG_PRINT 
				printf("min index: %d\n", min_index);				
				#endif
				// swap the ip src_addr back because we're a switch! 				
				ipv4_header->src_addr = ipv4_header->dst_addr; 
				// Assign ip dst addr
				if(min_index == 1){
					ipv4_header->dst_addr = h.alt->alt_dst_ip;
				}
				else if(min_index == 2){
					ipv4_header->dst_addr = h.alt->alt_dst_ip2;
				}
				else if(min_index == 3){
					ipv4_header->dst_addr = h.alt->alt_dst_ip3;
				}

				#ifdef REDIRECT_DEBUG_PRINT 
				uint8_t temp_addrs[4];
				uint32_t temp_ipaddr = rte_be_to_cpu_32(ipv4_header->dst_addr);
				temp_addrs[0] = (uint8_t) (temp_ipaddr >> 24) & 0xff;
				temp_addrs[1] = (uint8_t) (temp_ipaddr >> 16) & 0xff;
				temp_addrs[2] = (uint8_t) (temp_ipaddr >> 8) & 0xff;
				temp_addrs[3] = (uint8_t) temp_ipaddr & 0xff;
				printf("ipv4_header->dst_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
						temp_addrs[0], temp_addrs[1], temp_addrs[2], temp_addrs[3]);
				#endif

				// look up dst mac addr for our ip dest addr				
				ret = rte_hash_lookup_data(fs->ip2mac_table, (void*) &ipv4_header->dst_addr, &lookup_result);
				if(ret >= 0){
					struct rte_ether_addr* lookup1 = (struct rte_ether_addr*)(uintptr_t) lookup_result;
					#ifdef REDIRECT_DEBUG_PRINT 
					printf("eth_addr lookup: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
						" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					lookup1->addr_bytes[0], lookup1->addr_bytes[1],
					lookup1->addr_bytes[2], lookup1->addr_bytes[3],
					lookup1->addr_bytes[4], lookup1->addr_bytes[5]);
					#endif
					// Assign lookup result to dest ether addr
					// rte_ether_addr_copy (const struct rte_ether_addr *ea_from, struct rte_ether_addr *ea_to)
					rte_ether_addr_copy(lookup1, &ether_header->d_addr);
				}
				else{
					if (errno == ENOENT)
						printf("value not found\n");
					else
						printf("invalid parameters\n");
				}

				//TEST-ONLY HARDCODE that redirect to yeti-05
				//char* mac_addr_yeti05 = "ec:0d:9a:68:21:a0";
				//rte_ether_unformat_addr(mac_addr_yeti05, &ether_header->d_addr);

				// swap it back so UDP packets are delivered to the correct port after redirection!
				swap_udp(udp_header);

				// update checksum!
				udp_header->dgram_cksum = 0;
            	udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_header, (void*)udp_header);
				ipv4_header->hdr_checksum = 0;
				ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);

				#ifdef REDIRECT_DEBUG_PRINT 
				printf("-------- redirection modification start------\n");

				printf("eth_addr src: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
						" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					ether_header->s_addr.addr_bytes[0], ether_header->s_addr.addr_bytes[1],
					ether_header->s_addr.addr_bytes[2], ether_header->s_addr.addr_bytes[3],
					ether_header->s_addr.addr_bytes[4], ether_header->s_addr.addr_bytes[5]);

				printf("eth_addr dst: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
						" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					ether_header->d_addr.addr_bytes[0], ether_header->d_addr.addr_bytes[1],
					ether_header->d_addr.addr_bytes[2], ether_header->d_addr.addr_bytes[3],
					ether_header->d_addr.addr_bytes[4], ether_header->d_addr.addr_bytes[5]);

				uint32_t src_ipaddr = rte_be_to_cpu_32(ipv4_header->src_addr);
				uint32_t dst_ipaddr = rte_be_to_cpu_32(ipv4_header->dst_addr);
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
				printf("-------- redirection modification end------\n");
				#endif /* REDIRECT_DEBUG_PRINT */			
			}			
			else if(get_alt_header_msgtype(h.alt) == HOST_FEEDBACK_MSG){
				//TODO: [UNTESTED], we need proper way to free packets				 
				uint64_t load = (uint64_t) h.alt->feedback_options;
				//printf("load: %" PRIu64 " from", load);
				//after ip swap: dst is the src here
				ipv4_header->src_addr = ipv4_header->dst_addr;
				//uint32_t src_ipaddr = rte_be_to_cpu_32(ipv4_header->src_addr);				
				// uint8_t src_addr[4];
				// src_addr[0] = (uint8_t) (src_ipaddr >> 24) & 0xff;
				// src_addr[1] = (uint8_t) (src_ipaddr >> 16) & 0xff;
				// src_addr[2] = (uint8_t) (src_ipaddr >> 8) & 0xff;
				// src_addr[3] = (uint8_t) src_ipaddr & 0xff;
				// printf("src_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
				// 		src_addr[0], src_addr[1], src_addr[2], src_addr[3]);

				ip_service_key.service_id = h.alt->service_id;
				ip_service_key.ip_dst = h.alt->alt_dst_ip;
				//update values
				int ret = rte_hash_add_key_data(fs->ip2load_table, (void*) &ip_service_key, (void *)((uintptr_t) &load));
				drop_index_list[drop_index] = i;
				drop_index++;
				//rte_pktmbuf_free(pkts_burst[i]);
			}
			else if(get_alt_header_msgtype(h.alt) == SINGLE_PKT_RESP_PASSTHROUGH){
				// 1. assign the alt_dst_ip which is the real dest ip to ipv4_header->dst_addr
				// 2. lookup the mac address of alt_dst_ip in ip2mac table
				// 3. modify the dest mac addr

				// uint64_t recv_counter = (uint64_t) h.alt->feedback_options;
				// printf("recv_counter: %" PRIu64 " from \n", recv_counter);

				// swap the ip src_addr back because we're a switch! 				
				ipv4_header->src_addr = ipv4_header->dst_addr;
				ipv4_header->dst_addr = h.alt->alt_dst_ip;

				// uint32_t src_ipaddr = rte_be_to_cpu_32(ipv4_header->src_addr);				
				// uint8_t src_addr[4];
				// src_addr[0] = (uint8_t) (src_ipaddr >> 24) & 0xff;
				// src_addr[1] = (uint8_t) (src_ipaddr >> 16) & 0xff;
				// src_addr[2] = (uint8_t) (src_ipaddr >> 8) & 0xff;
				// src_addr[3] = (uint8_t) src_ipaddr & 0xff;		
				// printf("ipv4_header->src_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
				// 		src_addr[0], src_addr[1], src_addr[2], src_addr[3]);

				// uint8_t temp_addrs[4];
				// uint32_t temp_ipaddr = rte_be_to_cpu_32(ipv4_header->dst_addr);
				// temp_addrs[0] = (uint8_t) (temp_ipaddr >> 24) & 0xff;
				// temp_addrs[1] = (uint8_t) (temp_ipaddr >> 16) & 0xff;
				// temp_addrs[2] = (uint8_t) (temp_ipaddr >> 8) & 0xff;
				// temp_addrs[3] = (uint8_t) temp_ipaddr & 0xff;
				// printf("ipv4_header->dst_addr: %" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n",
				// 		temp_addrs[0], temp_addrs[1], temp_addrs[2], temp_addrs[3]);

				int ret = rte_hash_lookup_data(fs->ip2mac_table, (void*) &ipv4_header->dst_addr, &lookup_result);
				if(ret >= 0){
					struct rte_ether_addr* lookup1 = (struct rte_ether_addr*)(uintptr_t) lookup_result;
					#ifdef REDIRECT_DEBUG_PRINT
					// printf("SINGLE_PKT_RESP_PASSTHROUGH\n");					 
					printf("eth_dst_addr lookup: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
						" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
					lookup1->addr_bytes[0], lookup1->addr_bytes[1],
					lookup1->addr_bytes[2], lookup1->addr_bytes[3],
					lookup1->addr_bytes[4], lookup1->addr_bytes[5]);
					#endif
					// Assign lookup result to dest ether addr
					rte_ether_addr_copy(lookup1, &ether_header->d_addr);
				}
				else{
					if (errno == ENOENT)
						printf("value not found\n");
					else
						printf("invalid parameters\n");
				}

				// swap it back so UDP packets are delivered to the correct port after redirection!
				swap_udp(udp_header);

				// update checksum!
				udp_header->dgram_cksum = 0;
            	udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_header, (void*)udp_header);
				ipv4_header->hdr_checksum = 0;
				ipv4_header->hdr_checksum = rte_ipv4_cksum(ipv4_header);
				passthrough_counter++;
			}	

			//TODO:
			// 1. assign the alt_dst_ip which is the real dest ip to ipv4_header->dst_addr
			// 2. lookup the mac address of alt_dst_ip in ip2mac table
			// 3. modify the dest mac addr
			// 4. update the ip2load_table like HOST_FEEDBACK_MSG
			//else if(get_alt_header_msgtype(h.alt) == SINGLE_PKT_RESP_PIGGYBACK){				 
			//}

			//TODO:
			// 1. update the ip2load_table like HOST_FEEDBACK_MSG
			// 2. update the last updated time of a switch entry in a table
			//else if(get_alt_header_msgtype(h.alt) == SWITCH_FEEDBACK_MSG){				 
			//}

			#endif /* REDIRECT_ENABLED */
		} else if (next_proto == IPPROTO_TCP) {
			swap_tcp(h.tcp);
			mb->l4_len = (h.tcp->data_off & 0xf0) >> 2;
		}
		mbuf_field_set(mb, ol_flags);
	}

	//printf("--------\n");

	// TODO: Handle packets don't need to be sent out
	// Method 1:
	// 1. increment drop_pkt counter, record its index in pkts_burst array to a separated array
	// 2. if(drop_pkt==0)
	//    	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx)
	// 3. if(drop_pkt > 0)
	//     calculate how many consecutive sub-array we have
	//     T is for pkts for TX, and D is for pkts need to be DROP
	//     e.g. TTTDTTTDTT
	//     we'll need 3 rte_eth_tx_burst calls and 2 rte_pktmbuf_free calls
	//     -> for(number of rte_eth_tx_burst calls)
	//			rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);

	//tested: 
	// 1. (V) the server host sends only HOST_FEEDBACK_MSG packets
	// 2. (V) the server host sends SINGLE_PKT_RESP_PASSTHROUGH and HOST_FEEDBACK_MSG together
	// a. (V) low rate, b. () high rate
	// 3. (V) the client sends SINGLE_PKT_REQ and server sends both SINGLE_PKT_RESP_PASSTHROUGH and HOST_FEEDBACK_MSG
	if(drop_index == 0){
		nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
	}
	else{
		//send out burst of packets separated by packets needs to be drop/freed
		int lower_bound = 0;
		int num_pkt = drop_index_list[0]; //- lower_bound;
		if(num_pkt > 0)
			nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, num_pkt);			
		lower_bound = lower_bound + num_pkt + 1;

		for(int j = 1; j < drop_index; j++){
			num_pkt = drop_index_list[j] - lower_bound;

			if(num_pkt > 0)
				nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, &pkts_burst[lower_bound], num_pkt);

			lower_bound = lower_bound + num_pkt + 1;
		}

		//free those packets
		for(int j = 0; j < drop_index; j++){
			//printf("free packet %d\n", j);
			int pkt_index = drop_index_list[j];
			rte_pktmbuf_free(pkts_burst[pkt_index]);
			drop_index_list[j] = 0;
		}

		drop_index = 0;
	}
	
	// Method 2:
	// rte_eth_tx_buffer() per packet
	// dpdk_flush if (++RTE_PER_LCORE(packet_count) == 32)

	//old rte_eth_tx_burst
	//nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
	clock_gettime(CLOCK_REALTIME, &ts2);

	if(ts1.tv_sec == ts2.tv_sec){
		//fs->latency_records
		//fprintf(fp, "%" PRIu64 "\n", ts2.tv_nsec - ts1.tv_nsec); 	
		if (next_proto == IPPROTO_UDP) 	
			//printf("queue_id %" PRIu16 ":%" PRIu64 "\n", fs->rx_queue, ts2.tv_nsec - ts1.tv_nsec);
			printf("%" PRIu64 "\n", ts2.tv_nsec - ts1.tv_nsec);
	}
	else{ 
		uint64_t ts1_nsec = ts1.tv_nsec + 1000000000*ts1.tv_sec;
		uint64_t ts2_nsec = ts2.tv_nsec + 1000000000*ts2.tv_sec;                    
		//fprintf(fp, "%" PRIu64 "\n", ts2_nsec - ts1_nsec);
		if (next_proto == IPPROTO_UDP) 
			printf("%" PRIu64 "\n", ts2_nsec - ts1_nsec);
			//printf("queue_id %" PRIu16 ":%" PRIu64 "\n", fs->rx_queue, ts2_nsec - ts1_nsec);
	}

}

struct fwd_engine five_tuple_swap_fwd_engine = {
	.fwd_mode_name  = "5tswap",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_5tuple_swap,
};
