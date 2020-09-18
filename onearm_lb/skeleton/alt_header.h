#ifndef MULTI_DEST_HEADER_H
#define MULTI_DEST_HEADER_H

struct alt_header {
  uint16_t service_id;    // Type of Service.
  uint32_t request_id;    // Request identifier.
  //uint16_t packet_id;     // Packet identifier.
  uint16_t options;       // Options (could be request length etc.).
  //in_port_t dst_port;
  uint32_t alt_dst_ip;
  uint32_t alt_dst_ip2;
  uint32_t alt_dst_ip3;
} __attribute__((__packed__));
//typedef struct alt_header alt_header;

#endif //MULTI_DEST_HEADER_H
