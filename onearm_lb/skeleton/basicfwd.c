/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "alt_header.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

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
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());

	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {
													
			/* Get burst of RX packets, from first and only port */
			struct rte_mbuf *rx_pkts[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					rx_pkts, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			/* Ethernet header
			struct rte_ether_addr {
   				uint8_t addr_bytes[RTE_ETHER_ADDR_LEN]; 
   			} __attribute__((aligned(2)));

			struct rte_ether_hdr {
  				struct rte_ether_addr d_addr; 
				struct rte_ether_addr s_addr; 
				uint16_t ether_type;      
			} __attribute__((aligned(2)));
			*/
			
			/* IPv4 header
			struct rte_ipv4_hdr {
				uint8_t  version_ihl;       
				uint8_t  type_of_service;   
				rte_be16_t total_length;    
				rte_be16_t packet_id;       
				rte_be16_t fragment_offset; 
				uint8_t  time_to_live;      
				uint8_t  next_proto_id;     
				rte_be16_t hdr_checksum;    
				rte_be32_t src_addr;        
				rte_be32_t dst_addr;        
			} __attribute__((__packed__));
			*/	

			for (uint16_t i = 0; i < nb_rx; i++){
				struct rte_ether_hdr* eth_hdr;
				uint32_t packet_type = RTE_PTYPE_UNKNOWN;
				uint16_t ether_type;
				void *l3;	
				int hdr_len;
				struct rte_ipv4_hdr *ipv4_hdr;
				uint16_t dst_port = 0;
				uint16_t src_port = 0; 
				uint32_t dst_ipaddr;
				uint32_t src_ipaddr;
				struct rte_ether_addr src_macaddr;
				struct rte_ether_addr dst_macaddr;	

				eth_hdr = rte_pktmbuf_mtod(rx_pkts[i], struct rte_ether_hdr *);
				ether_type = eth_hdr->ether_type;
				l3 = (uint8_t *)eth_hdr + sizeof(struct rte_ether_hdr);

				if(ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)){
					ipv4_hdr = (struct rte_ipv4_hdr *)l3;
					src_macaddr = eth_hdr->s_addr;
					dst_macaddr = eth_hdr->d_addr;					

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

					hdr_len = (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

					if (hdr_len == sizeof(struct rte_ipv4_hdr)) {
						packet_type |= RTE_PTYPE_L3_IPV4;

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

						// if (ipv4_hdr->next_proto_id == IPPROTO_TCP){
						// 	packet_type |= RTE_PTYPE_L4_TCP;
						// 	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
						// 	dst_port = rte_be_to_cpu_16(tcp->dst_port);
						// 	src_port = rte_be_to_cpu_16(tcp->src_port);
						// }	

						if (ipv4_hdr->next_proto_id == IPPROTO_UDP){
							packet_type |= RTE_PTYPE_L4_UDP;
							struct rte_udp_hdr* udp = (struct rte_udp_hdr *)((uint8_t *)ipv4_hdr + sizeof(struct rte_ipv4_hdr));
							dst_port = rte_be_to_cpu_16(udp->dst_port);
							src_port = rte_be_to_cpu_16(udp->src_port);

							struct alt_header* alt = (struct alt_header *)((uint8_t *)udp + sizeof(struct rte_udp_hdr));
							uint32_t req_id = alt->request_id;
							uint16_t service_id = alt->service_id;

							printf("src_port:%" PRIu16 ", dst_port:%" PRIu16 "\n", src_port, dst_port);
							printf("service_id:%" PRIu16 "req_id:%" PRIu32 "\n", service_id, req_id);
							printf("-------------------\n");
						}						

					} 
					else{
						packet_type |= RTE_PTYPE_L3_IPV4_EXT;
					}
				}
				else{
					//printf("not eth_ipv4 type%" PRIu16 "\n", ether_type);
				}	

				rte_pktmbuf_free(rx_pkts[i]);
			}				


			/* Send burst of TX packets, to the same port */
			// const uint16_t nb_tx = rte_eth_tx_burst(port, 0,
			// 		bufs, nb_rx);

			/* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
			// 	uint16_t buf;
			// 	for (buf = nb_tx; buf < nb_rx; buf++)
			// 		rte_pktmbuf_free(bufs[buf]);
			// }
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

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;
}
