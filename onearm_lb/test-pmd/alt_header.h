#ifndef MULTI_DEST_HEADER_H
#define MULTI_DEST_HEADER_H

#include <stdint.h>

#define FIRST_FLAG 0x20
#define LAST_FLAG 0x10
#define HOST_PER_RACK 2
#define NUM_REPLICA 3
#define LOAD_THRESHOLD 1 // 30 requests threshold
#define REDIRECT_BOUND 2  // how many times a request can be redirected

//value -> uint16_t load_level but store with uint64_t format
struct table_key {
    uint32_t ip_dst;
    uint16_t service_id;	
} __attribute__((__packed__));

// total 28 bytes + 80 bytes = 108 bytes
struct alt_header {
  // 1 + 1 + 2 + 4 = 8 bytes
  uint8_t  msgtype_flags;
  uint8_t  redirection;
  uint8_t  header_size; // how long the whole header is, HOST_PER_RACK is not a fixed value
  uint8_t  reserved;

  //4 bytes
  uint16_t feedback_options;	
  uint16_t service_id;    // Type of Service.
  uint32_t request_id;    // Request identifier.
  
  // 8 bytes + 12 bytes = 20 bytes
  uint32_t alt_dst_ip; // default destination
  uint32_t actual_src_ip;
  uint32_t replica_dst_list[NUM_REPLICA];
  // stay here for testing older version!
  //uint32_t alt_dst_ip2;
  //uint32_t alt_dst_ip3;  

  //load information appended here!
  uint16_t service_id_list[HOST_PER_RACK];   // 20 bytes
  uint32_t host_ip_list[HOST_PER_RACK];     // 40 bytes
  uint16_t host_queue_depth[HOST_PER_RACK]; // 20 bytes
} __attribute__((__packed__)); // or use __rte_packed
//typedef struct alt_header alt_header;

//FOR SWITCH_FEEDBACK_MSG and piggyback cases
struct switch_exchange {
  uint8_t  msgtype_flags;
  uint32_t host_ip_list[HOST_PER_RACK];
  uint16_t host_queue_depth[HOST_PER_RACK];
}__attribute__((__packed__));


// msgtype_flags field details: suspended for now
// -> bit 0,1: unused now
// -> bit 2,3: FIRST_FLAG and LAST_FLAG for multi-packet req
// -> bit 4-7: msg_type listed in the enum below

enum {
  SINGLE_PKT_REQ = 0, // default is doing replica selection
  SINGLE_PKT_REQ_PASSTHROUGH,
  SINGLE_PKT_RESP_PIGGYBACK,
  SINGLE_PKT_RESP_PASSTHROUGH,  
  HOST_FEEDBACK_MSG,
  SWITCH_FEEDBACK_MSG,
  MULTI_PKT_REQ,
  MULTI_PKT_RESP_PIGGYBACK,
  MULTI_PKT_RESP_PASSTHROUGH,  
  CONTROL_MSG_ROUTING_UPDATE,  // for updating routing table at runtime
  CONTROL_MSG_SWITCH_ADDITION, // for adding addtional switch and servers at runtime
  CONTROL_MSG_NODE_ADDITION,   // for adding addiotnal node to a switch at runtime
};

// static inline void set_alt_header_isfirst(struct alt_header *h){
// 	h->msgtype_flags = h->msgtype_flags | FIRST_FLAG;
// }

// static inline void set_alt_header_islast(struct alt_header *h){
// 	h->msgtype_flags = h->msgtype_flags | LAST_FLAG;
// }

// static inline uint8_t get_alt_header_isfirst(struct alt_header *h){
// 	return (h->msgtype_flags & FIRST_FLAG) >> 6;
// }

// static inline uint8_t get_alt_header_islast(struct alt_header *h){
// 	return (h->msgtype_flags & LAST_FLAG) >> 5;
// }

static inline void set_alt_header_msgtype(struct alt_header *h, uint8_t value){
  //value = value & 0x0F; // leave the lower 4-bit
  //h->msgtype_flags = h->msgtype_flags | value;
  h->msgtype_flags = value;
}

static inline uint8_t get_alt_header_msgtype(struct alt_header *h){
	//return (h->msgtype_flags & 0x0F) >> 4;
  return h->msgtype_flags;
}

#endif //MULTI_DEST_HEADER_H
