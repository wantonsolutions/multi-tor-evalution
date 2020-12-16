#ifndef CLOVER_STRUCTS_H
#define CLOVER_STRUCTS_H

#include <stdint.h>

#define MITSUME_CLT_CONSUMER_PER_ASK_NUMS 16
#define MITSUME_CLT_CONSUMER_MAX_ENTRY_NUMS MITSUME_CLT_CONSUMER_PER_ASK_NUMS
#define MITSUME_NUM_REPLICATION_BUCKET 1


struct ib_mr_attr {
  uint64_t addr;
  uint32_t rkey;
  short machine_id;
};

typedef struct ib_mr_attr ptr_attr;

struct mitsume_msg_header {
  int type;
  int src_id;
  int des_id;
  uint32_t thread_id;
  ptr_attr reply_attr;
};

struct mitsume_msg_init {
  uint64_t init_number_of_lh;
  uint64_t init_start_lh;
  int available_xactareas_start_num;
  int available_xactareas_num;
};

struct mitsume_ptr {
  uint64_t pointer;
};

struct mitsume_msg_entry {
  // uint32_t entry_lh[MITSUME_CLT_CONSUMER_MAX_ENTRY_NUMS];
  // uint64_t entry_offset[MITSUME_CLT_CONSUMER_MAX_ENTRY_NUMS];
  struct mitsume_ptr ptr[MITSUME_CLT_CONSUMER_MAX_ENTRY_NUMS];
  uint32_t entry_size;
  uint32_t entry_number;
  int entry_replication_bucket;
  int already_available_buckets[MITSUME_NUM_REPLICATION_BUCKET];
  // int available_buckets[MITSUME_MAX_REPLICATION];
};

typedef uint64_t mitsume_key;

#define MITSUME_NUM_REPLICATION_BUCKET 1
#define MITSUME_MAX_REPLICATION MITSUME_NUM_REPLICATION_BUCKET

struct mitsume_entry_request {
  uint32_t type;
  mitsume_key key;
  struct mitsume_ptr ptr[MITSUME_MAX_REPLICATION];
  struct mitsume_ptr shortcut_ptr;
  int replication_factor;
  uint32_t version;
  int debug_flag;
};


struct mitsume_msg {
  struct mitsume_msg_header msg_header; // dont change this position . it has to
                                        // be aligned with mitsume_msg msg_header
  union {
    struct mitsume_msg_init msg_init; // small
    struct mitsume_msg_entry
        msg_entry; // use for allocation and garbage collection
    struct mitsume_entry_request
        msg_entry_request; // use for open specifically //small

    /*TODO finish copying msg struct from mitsume_struc.h*/
    //struct mitsume_gc_epoch_forward msg_gc_epoch_forward; // small
    //struct mitsume_msg_gc_control msg_gc_control;
    //struct mitsume_misc_request_struct msg_misc_request; // for misc-usage, such as wrap version, migration
                          // request
    //struct mitsume_stat_message msg_stat_message;
    int success_gc_number;
  } content;

  uint64_t option;
  uint64_t end_crc;
};

#endif