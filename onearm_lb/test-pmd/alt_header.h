#ifndef MULTI_DEST_HEADER_H
#define MULTI_DEST_HEADER_H

#include <stdint.h>

#define FIRST_FLAG 0x20
#define LAST_FLAG 0x10


//value -> uint16_t load_level but store with uint64_t format
struct table_key {
    uint32_t ip_dst;
    uint16_t service_id;	
} __attribute__((__packed__));

// total 20 bytes
struct alt_header {
  // 1 + 1 + 2 + 4 = 8 bytes
  uint8_t  msgtype_flags; 	 	
  uint8_t  feedback_options;	
  uint16_t service_id;    // Type of Service.
  uint32_t request_id;    // Request identifier.

  // 12 bytes
  uint32_t alt_dst_ip;
  uint32_t alt_dst_ip2;
  uint32_t alt_dst_ip3;
} __attribute__((__packed__)); // or use __rte_packed
//typedef struct alt_header alt_header;

// msgtype_flags field details:
// -> bit 0,1: unused now
// -> bit 2,3: FIRST_FLAG and LAST_FLAG for multi-packet req
// -> bit 4-7: msg_type listed in the enum below

enum {
  SINGLE_PKT_REQ = 0,
  SINGLE_PKT_RESP_PIGGYBACK,
  SINGLE_PKT_RESP_PASSTHROUGH,  
  HOST_FEEDBACK_MSG,
  SWITCH_FEEDBACK_MSG,
  MULTI_PKT_REQ,
  MULTI_PKT_RESP_PIGGYBACK,
  MULTI_PKT_RESP_PASSTHROUGH,  
  DROP_PKT_MSG,
  ACK_PKT_MSG,
};

static inline void set_alt_header_isfirst(struct alt_header *h){
	h->msgtype_flags = h->msgtype_flags | FIRST_FLAG;
}

static inline void set_alt_header_islast(struct alt_header *h){
	h->msgtype_flags = h->msgtype_flags | LAST_FLAG;
}

static inline uint8_t get_alt_header_isfirst(struct alt_header *h){
	return (h->msgtype_flags & FIRST_FLAG) >> 6;
}

static inline uint8_t get_alt_header_islast(struct alt_header *h){
	return (h->msgtype_flags & LAST_FLAG) >> 5;
}

static inline void set_alt_header_msgtype(struct alt_header *h, uint8_t value){
  value = value & 0x0F; // leave the lower 4-bit
  h->msgtype_flags = h->msgtype_flags | value;
}

static inline uint8_t get_alt_header_msgtype(struct alt_header *h){
	return (h->msgtype_flags & 0x0F) >> 4;
}

#endif //MULTI_DEST_HEADER_H
