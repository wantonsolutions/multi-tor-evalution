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

uint32_t tx_ip_src_addr = RTE_IPV4(10, 0, 0, 18);
uint32_t tx_ip_dst_addr = RTE_IPV4(10, 0, 0, 4);
uint32_t tx_ip_dst2_addr = RTE_IPV4(10, 0, 0, 5);

#define IP_DEFTTL  64   /* from RFC 1340. */

static struct rte_ipv4_hdr pkt_ip_hdr; /**< IP header of transmitted packets. */
static struct rte_udp_hdr pkt_udp_hdr; /**< UDP header of tx packets. */
static struct alt_header pkt_alt_hdr;

struct timespec ts1, sleep_ts1, sleep_ts2;

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
setup_pkt_alt_headers(struct alt_header* alt_hdr, uint32_t dest_ip){
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
	ip_hdr->src_addr = rte_cpu_to_be_32(tx_ip_src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(tx_ip_dst_addr);

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

	/*
	 * Complete first mbuf of packet and append it to the
	 * burst of packets to be transmitted.
	 */
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
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;

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
	rte_ether_addr_copy(&peer_eth_addrs[fs->peer_addr], &eth_hdr.d_addr);
	rte_ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr.s_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	if (rte_mempool_get_bulk(mbp, (void **)pkts_burst,
				nb_pkt_per_burst) == 0) {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			if (unlikely(!pkt_burst_prepare(pkts_burst[nb_pkt], mbp,
							&eth_hdr, vlan_tci,
							vlan_tci_outer,
							ol_flags,
							nb_pkt, fs))) {
				rte_mempool_put_bulk(mbp,
						(void **)&pkts_burst[nb_pkt],
						nb_pkt_per_burst - nb_pkt);
				break;
			}
		}
	} else {
		for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
			pkt = rte_mbuf_raw_alloc(mbp);
			if (pkt == NULL)
				break;
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
	}

	if (nb_pkt == 0)
		return;

	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);

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
	setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);
}

struct fwd_engine tx_only_engine = {
	.fwd_mode_name  = "txonly",
	.port_fwd_begin = tx_only_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_transmit,
};



static void
rtt_measure_begin(portid_t pi){
	uint16_t pkt_data_len;
	int dynf;

	pkt_data_len = (uint16_t) (tx_pkt_length - (
					sizeof(struct rte_ether_hdr) +
					sizeof(struct rte_ipv4_hdr) +
					sizeof(struct rte_udp_hdr)));
	setup_pkt_udp_ip_headers(&pkt_ip_hdr, &pkt_udp_hdr, pkt_data_len);

	nb_pkt_per_burst = 1;
} 

static void
rtt_transmit_receive(struct fwd_stream *fs){

	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *recv_burst[MAX_PKT_BURST];
	struct rte_port *txp;
	struct rte_mbuf *pkt;
	struct rte_mempool *mbp;
	struct rte_ether_hdr eth_hdr;
	uint16_t nb_tx, nb_rx;
	uint16_t nb_pkt;
	uint16_t vlan_tci, vlan_tci_outer;
	uint32_t retry;
	uint64_t ol_flags = 0;
	uint64_t tx_offloads;

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
	//TODO: set them right, we need to lookup for dest addr
	void* lookup_result;
	int ret = rte_hash_lookup_data(fs->ip2mac_table, (void*) &pkt_ip_hdr.dst_addr, &lookup_result);
	if(ret >= 0){
		struct rte_ether_addr* lookup1 = (struct rte_ether_addr*)(uintptr_t) lookup_result;
		//#ifdef REDIRECT_DEBUG_PRINT 
		//printf("eth_addr.d_addr lookup: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		//	" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		//lookup1->addr_bytes[0], lookup1->addr_bytes[1],
		//lookup1->addr_bytes[2], lookup1->addr_bytes[3],
		//lookup1->addr_bytes[4], lookup1->addr_bytes[5]);
		rte_ether_addr_copy(lookup1, &eth_hdr.d_addr);
	}
	
	//printf("eth_hdr.s_addr: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	//" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
	//ports[fs->tx_port].eth_addr.addr_bytes[0], ports[fs->tx_port].eth_addr.addr_bytes[1],
	//ports[fs->tx_port].eth_addr.addr_bytes[2], ports[fs->tx_port].eth_addr.addr_bytes[3],
	//ports[fs->tx_port].eth_addr.addr_bytes[4], ports[fs->tx_port].eth_addr.addr_bytes[5]);

	rte_ether_addr_copy(&ports[fs->tx_port].eth_addr, &eth_hdr.s_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	nb_pkt_per_burst = 1;
	for (nb_pkt = 0; nb_pkt < nb_pkt_per_burst; nb_pkt++) {
		pkt = rte_mbuf_raw_alloc(mbp);
		if (pkt == NULL)
			break;
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

	if (nb_pkt == 0)
		return;
	
	//printf("rte_eth_tx_burst wants to tx%" PRIu16 " pkt\n", nb_pkt);
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_pkt);

	if(nb_tx){
		printf("rte_eth_tx_burst tx %" PRIu16 " pkt\n", nb_tx);
		uint64_t ns_timestamp = clock_gettime_ns(&ts1);
		printf("%" PRIu64 "\n", ns_timestamp);
	}

	// clock_gettime(CLOCK_REALTIME, &ts1);
	// sleep_ts1=ts1;
	// realnanosleep(500*1000*1000, &sleep_ts1, &sleep_ts2); // 500 millisecond
	/*
	 * Retry if necessary
	 */
	// if (unlikely(nb_tx < nb_pkt) && fs->retry_enabled) {
	// 	retry = 0;
	// 	while (nb_tx < nb_pkt && retry++ < burst_tx_retry_num) {
	// 		rte_delay_us(burst_tx_delay_time);
	// 		nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
	// 				&pkts_burst[nb_tx], nb_pkt - nb_tx);
	// 	}
	// }
	fs->tx_packets += nb_tx;

	// if (unlikely(nb_tx > nb_pkt)) {
	// 	if (verbose_level > 0 && fs->fwd_dropped == 0)
	// 		printf("port %d tx_queue %d - drop "
	// 		       "(nb_pkt:%u - nb_tx:%u)=%u packets\n",
	// 		       fs->tx_port, fs->tx_queue,
	// 		       (unsigned) nb_pkt, (unsigned) nb_tx,
	// 		       (unsigned) (nb_pkt - nb_tx));
	// 	fs->fwd_dropped += (nb_pkt - nb_tx);
	// 	do {
	// 		rte_pktmbuf_free(pkts_burst[nb_tx]);
	// 	} while (++nb_tx < nb_pkt);
	// }

	// nb_rx = 0;
	// int counter = 5;
	// while(counter > 0){ // keep rx until we got one packet!
	// 	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, recv_burst, 1);
	// 	counter--;
	// 	if(nb_rx > 0){
	// 		printf("rte_eth_rx_burst rx %" PRIu16 " pkt\n", nb_rx);
	// 	}
	// 	rte_delay_us(5);
	// }
	// printf("port %" PRIu16 ", queue %" PRIu16 "\n", fs->rx_port, fs->rx_queue);
	// //int ret_count = rte_eth_rx_queue_count(fs->rx_port, fs->rx_queue);
	// //if (ret_count == -ENOTSUP){
	// //	printf("the device does not support this function\n");
	// //}
	// //printf("rte_eth_rx_burst rx %" PRIu16 " pkt\n", nb_rx);
	// //printf("rte_strerror: %s\n", rte_strerror(rte_errno));
	// fs->rx_packets += nb_rx;
	// for (int i = 0; i < nb_rx; i++)
	// 	rte_pktmbuf_free(recv_burst[i]);

}

struct fwd_engine rtt_measure_fwd_engine = {
	.fwd_mode_name  = "rtt-measure",
	.port_fwd_begin = rtt_measure_begin,
	.port_fwd_end   = NULL,
	.packet_fwd     = rtt_transmit_receive,
};
