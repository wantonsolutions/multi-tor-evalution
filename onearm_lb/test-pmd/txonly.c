/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

//ST: for ip->mac lookup
#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include "nanosleep.h"
#include "alt_header.h"

#include <rte_errno.h>
#include "testpmd.h"

uint16_t tx_udp_src_port = 7000;
uint16_t tx_udp_dst_port = 7000;

//TODO: for future periodic updates to other switch 
//the program goes through key space of ip2mac table
//for packets that should go to every other switches (in a burst?)
uint32_t tx_ip_dst_addr = RTE_IPV4(10, 0, 0, 4);
uint32_t tx_ip_src_addr = RTE_IPV4(10, 0, 0, 18);

char* mac_src_addr = "ec:0d:9a:68:21:c0"; //10.0.0.18 -> ec:0d:9a:68:21:c0
char* mac_dst_addr = "ec:0d:9a:68:21:a8"; //10.0.0.4  -> ec:0d:9a:68:21:a8
struct rte_ether_hdr eth_hdr;

#define IP_DEFTTL  64   /* from RFC 1340. */

struct timespec ts1, ts2, sleep_ts1, sleep_ts2;

struct alt_header pkt_alt_hdr;
static struct rte_ipv4_hdr pkt_ip_hdr; /**< IP header of transmitted packets. */
//RTE_DEFINE_PER_LCORE(uint8_t, _ip_var); /**< IP address variation */
static struct rte_udp_hdr pkt_udp_hdr; /**< UDP header of tx packets. */
// RTE_DEFINE_PER_LCORE(uint64_t, timestamp_qskew);
// 					/**< Timestamp offset per queue */
// RTE_DEFINE_PER_LCORE(uint32_t, timestamp_idone); /**< Timestamp init done. */

// static uint64_t timestamp_mask; /**< Timestamp dynamic flag mask */
// static int32_t timestamp_off; /**< Timestamp dynamic field offset */
// static bool timestamp_enable; /**< Timestamp enable */
// static uint32_t timestamp_init_req; /**< Timestamp initialization request. */
// static uint64_t timestamp_initial[RTE_MAX_ETHPORTS];

static inline void
print_ether_addr(const char *what, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s\n", what, buf);
}

static inline void
print_ipaddr(const char* string, rte_be32_t ip_addr){
	uint32_t ipaddr = rte_be_to_cpu_32(ip_addr);
	uint8_t src_addr[4];
	src_addr[0] = (uint8_t) (ipaddr >> 24) & 0xff;
	src_addr[1] = (uint8_t) (ipaddr >> 16) & 0xff;
	src_addr[2] = (uint8_t) (ipaddr >> 8) & 0xff;
	src_addr[3] = (uint8_t) ipaddr & 0xff;
	printf("%s:%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 "\n", string,
			src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
}

static void
copy_buf_to_pkt_segs(void* buf, unsigned len, struct rte_mbuf *pkt,
		     unsigned offset)
{
	struct rte_mbuf *seg;
	void *seg_buf;
	unsigned copy_len;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t) copy_len);
		len -= copy_len;
		buf = ((char*) buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, char *);
		copy_len = seg->data_len;
	}
	rte_memcpy(seg_buf, buf, (size_t) len);
}

static inline void
copy_buf_to_pkt(void* buf, unsigned len, struct rte_mbuf *pkt, unsigned offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset),
			buf, (size_t) len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static void
setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
			 struct rte_udp_hdr *udp_hdr,
			 uint16_t pkt_data_len)
{
	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	/*
	 * Initialize UDP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(tx_udp_src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(tx_udp_dst_port);
	udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl   = RTE_IPV4_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);
	ip_hdr->src_addr = tx_ip_src_addr; //rte_cpu_to_be_32(tx_ip_src_addr);
	ip_hdr->dst_addr = tx_ip_dst_addr; //rte_cpu_to_be_32(tx_ip_dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (unaligned_uint16_t*) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];

	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

static inline bool
pkt_burst_prepare(struct rte_mbuf *pkt, struct rte_mempool *mbp,
		struct rte_ether_hdr *eth_hdr, const uint16_t vlan_tci,
		const uint16_t vlan_tci_outer, const uint64_t ol_flags,
		const uint16_t idx, const struct fwd_stream *fs)
{
	struct rte_mbuf *pkt_segs[RTE_MAX_SEGS_PER_PKT];
	struct rte_mbuf *pkt_seg;
	uint32_t nb_segs, pkt_len;
	uint8_t i;

	if (unlikely(tx_pkt_split == TX_PKT_SPLIT_RND))
		nb_segs = rte_rand() % tx_pkt_nb_segs + 1;
	else
		nb_segs = tx_pkt_nb_segs;

	if (nb_segs > 1) {
		if (rte_mempool_get_bulk(mbp, (void **)pkt_segs, nb_segs - 1))
			return false;
	}

	rte_pktmbuf_reset_headroom(pkt);
	pkt->data_len = tx_pkt_seg_lengths[0];
	pkt->ol_flags &= EXT_ATTACHED_MBUF;
	pkt->ol_flags |= ol_flags;
	pkt->vlan_tci = vlan_tci;
	pkt->vlan_tci_outer = vlan_tci_outer;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);

	pkt_len = pkt->data_len;
	pkt_seg = pkt;
	for (i = 1; i < nb_segs; i++) {
		pkt_seg->next = pkt_segs[i - 1];
		pkt_seg = pkt_seg->next;
		pkt_seg->data_len = tx_pkt_seg_lengths[i];
		pkt_len += pkt_seg->data_len;
	}
	pkt_seg->next = NULL; /* Last segment of packet. */
	/*
	 * Copy headers in first packet segment(s).
	 */
	copy_buf_to_pkt(eth_hdr, sizeof(*eth_hdr), pkt, 0);
	copy_buf_to_pkt(&pkt_ip_hdr, sizeof(pkt_ip_hdr), pkt,
			sizeof(struct rte_ether_hdr));
	copy_buf_to_pkt(&pkt_udp_hdr, sizeof(pkt_udp_hdr), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr));

	// iterate through the hashtable and load key-value pairs into alt_header fields
	uint32_t iter = 0;
	uint32_t index = 0;
	const void *next_key;
	void *next_data;
	while (rte_hash_iterate(fs->ip2load_table, &next_key, &next_data, &iter) >= 0) {
		struct table_key* ip_service_pair = (struct table_key*) (uintptr_t) next_key;
		uint64_t* load_value = (uint64_t*) (uintptr_t) next_data;
		for(uint32_t host_index = 0; host_index < HOST_PER_RACK; host_index++){
			if(ip_service_pair->ip_dst == fs->local_ip_list[host_index]){
				pkt_alt_hdr.service_id_list[index] = ip_service_pair->service_id;
				pkt_alt_hdr.host_ip_list[index] = ip_service_pair->ip_dst;
				print_ipaddr("rte_hash_iterate, ip_dst", pkt_alt_hdr.host_ip_list[index]);
				pkt_alt_hdr.host_queue_depth[index] = (uint16_t) *load_value;
				index++;
				break;
			}
		}
	}

	// for(uint32_t host_index = 0; host_index < HOST_PER_RACK; host_index++){
	// 	fs->local_ip_list[host_index];
	// 	int ret = rte_hash_lookup_data(fs->ip2load_table, (void*) &ip_service_key, &lookup_result);
	// }
	//pkt_alt_hdr.header_size = 24 + 8 * index;

	copy_buf_to_pkt(&pkt_alt_hdr, sizeof(pkt_alt_hdr), pkt,
			sizeof(struct rte_ether_hdr) +
			sizeof(struct rte_ipv4_hdr)  +
			sizeof(struct rte_udp_hdr));

	pkt->nb_segs = nb_segs;
	pkt->pkt_len = pkt_len;

	return true;
}

/*
 * Transmit a burst of multi-segments packets.
 */
static void
pkt_burst_transmit(struct fwd_stream *fs)
{
	nb_pkt_per_burst = 1;
	struct rte_mbuf *recv_burst[MAX_PKT_BURST];
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	//struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	uint16_t pkt_data_len;

	pkt_data_len = (uint16_t) (tx_pkt_length - (
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv4_hdr) +
					sizeof(struct rte_udp_hdr)));		
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	pkt_alt_hdr.msgtype_flags = SWITCH_FEEDBACK_MSG;
	pkt_alt_hdr.header_size = sizeof(struct alt_header);
	pkt_alt_hdr.redirection = 0;

	mbp = current_fwd_lcore()->mbp;
	txp = &ports[fs->tx_port];
	tx_offloads = txp->dev_conf.txmode.offloads;
	vlan_tci = txp->tx_vlan_id;
	vlan_tci_outer = txp->tx_vlan_id_outer;
	if (tx_offloads	& DEV_TX_OFFLOAD_VLAN_INSERT)
		ol_flags = PKT_TX_VLAN_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_QINQ_INSERT)
		ol_flags |= PKT_TX_QINQ_PKT;
	if (tx_offloads & DEV_TX_OFFLOAD_MACSEC_INSERT)
		ol_flags |= PKT_TX_MACSEC;

	/*
	 * Initialize Ethernet header.
	 */
	void* lookup_result;

	uint16_t local_nb_pkt_per_burst = fs->switch_ip_list_length;
	for (nb_pkt = 0; nb_pkt < local_nb_pkt_per_burst; nb_pkt++) {
		pkt = rte_mbuf_raw_alloc(mbp);
		if (pkt == NULL)
			break;

		//assign src_addr and dst_addr
		tx_ip_src_addr = fs->switch_self_ip;
		tx_ip_dst_addr = fs->switch_ip_list[nb_pkt];					
		//print_ipaddr("tx_ip_src_addr", tx_ip_src_addr);
		//print_ipaddr("tx_ip_dst_addr", tx_ip_dst_addr);
		setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);
		//print_ipaddr("pkt_ip_hdr.src_addr", pkt_ip_hdr.src_addr);
		//print_ipaddr("pkt_ip_hdr.dst_addr", pkt_ip_hdr.dst_addr);
		// look up mac address of the selected switch ip address
		int ret = rte_hash_lookup_data(fs->ip2mac_table, (void*) &pkt_ip_hdr.dst_addr, &lookup_result);
		if(ret >= 0){
			struct rte_ether_addr* lookup1 = (struct rte_ether_addr*)(uintptr_t) lookup_result;
			rte_ether_addr_copy(lookup1, &eth_hdr.d_addr);
			print_ether_addr("ETH_DST_ADDR in TX:", &eth_hdr.d_addr);
		}
		else{
			print_ether_addr("ETH_DST_ADDR in TX with lookup errors:", &eth_hdr.d_addr);
		}

		if (unlikely(!pkt_burst_prepare(pkt, mbp, &eth_hdr,
						vlan_tci,
						vlan_tci_outer,
						ol_flags,
						nb_pkt, fs))) {
			rte_pktmbuf_free(pkt);
			break;
		}
		pkts_burst[nb_pkt] = pkt;
	}
	//}

	if (nb_pkt == 0)
		return;

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, local_nb_pkt_per_burst);

	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_pkt - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;

	// if (txonly_multi_flow)
	// 	RTE_PER_LCORE(_ip_var) -= nb_pkt - nb_tx;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_pkt)) {
		if (verbose_level > 0 && fs->fwd_dropped == 0)
			printf("port %d tx_queue %d - drop "
			       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
			       fs->tx_port, fs->tx_queue,
			       (unsigned) nb_pkt, (unsigned) nb_tx,
			       (unsigned) (nb_pkt - nb_tx));
		fs->fwd_dropped += (nb_pkt - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_pkt);
	}

	// 1 (X) 2 (X) 3 (X) 4 (V) for vector sse -> mlx5_rx_burst_vec
	// 1 (V) for scalar -> mlx5_rx_burst
	// int nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, recv_burst, 4); 
	// if(nb_rx > 0){
	// 	printf("rte_eth_rx_burst rx %" PRIu16 " pkt\n", nb_rx);
	// }

	// fs->rx_packets += nb_rx;
	// for (int i = 0; i < nb_rx; i++)
	// 	rte_pktmbuf_free(recv_burst[i]);

	clock_gettime(CLOCK_REALTIME, &ts1);
	sleep_ts1=ts1;
	realnanosleep(500*1000*1000, &sleep_ts1, &sleep_ts2); // 500 ms

	// struct rte_eth_burst_mode mode;
	// rte_eth_rx_burst_mode_get(fs->rx_port, fs->rx_queue, &mode);
	// printf("%s\n", mode.info); // Vector SSE!

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
}

static void
tx_only_begin(portid_t pi)
{
	uint16_t pkt_data_len;
	int dynf;

	pkt_data_len = (uint16_t) (tx_pkt_length - (
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv4_hdr) +
					sizeof(struct rte_udp_hdr)));
	//setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);
	/*
	 * Initialize Ethernet header.
	 */
	// rte_ether_unformat_addr(mac_src_addr, &eth_hdr.s_addr);
	// print_ether_addr("ETH_SRC_ADDR:", &eth_hdr.s_addr);
	// rte_ether_unformat_addr(mac_dst_addr, &eth_hdr.d_addr);
	// print_ether_addr("ETH_DST_ADDR:", &eth_hdr.d_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

struct fwd_engine tx_only_engine = {
	.fwd_mode_name  = "txonly",
	.port_fwd_begin = NULL, //tx_only_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_transmit,
};
