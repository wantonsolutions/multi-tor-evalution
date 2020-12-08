#ifndef BASIC_FWD_H
#define BASIC_FWD_H


//#define PACKET_DEBUG_PRINTOUT 1
//#define TURN_PACKET_AROUND 1

#define DEBUG 2
#define INFO 1
#define NONE 0

//#define LOG_LEVEL DEBUG
#define LOG_LEVEL NONE

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32


int log_printf(int level, const char *format, ...);

struct rte_ether_hdr *eth_hdr_process(struct rte_mbuf* buf);
struct rte_ipv4_hdr* ipv4_hdr_process(struct rte_ether_hdr *eth_hdr);
struct rte_udp_hdr * udp_hdr_process(struct rte_ipv4_hdr *ipv4_hdr);



#endif