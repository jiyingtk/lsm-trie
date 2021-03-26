/*
 * Copyright (c) 2014  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "mempool.h"
#include "stat.h"
#include "cmap.h"

#define NR_PARTITIONS 4

struct BloomFilter {
  uint32_t bytes; // bytes = bits >> 3 (length of filter)
  uint32_t nr_keys;
  uint8_t filter[];
};

struct BloomFilterGroup {
  struct BloomFilter* group[NR_PARTITIONS];
};

// compact bloom_table
// format: encoded bits, bits
#define BLOOMTABLE_INTERVAL ((16u))
struct BloomTable {
  uint8_t *raw_bf;
  uint32_t nr_bf;
  uint32_t nr_bytes; // size of raw_bf
  uint32_t offsets[];
};

struct BloomGroupTable {
  uint8_t *raw_bf;
  uint32_t nr_bf;
  uint32_t nr_bytes; // size of raw_bf
  uint32_t* offsets[NR_PARTITIONS];
};

#define NR_PAGES_BF_MAX ((NR_PARTITIONS * 32 / 4))

// Container: storing boxes for multiple tables
// Box: multiple related bloom-filter in one box
struct BloomContainer {
  int raw_fd;
  uint16_t container_unit_count;
  uint64_t off_raw[NR_PAGES_BF_MAX];       // === off_main in MetaFileHeader
  uint32_t nr_barrels;    // === nr_main
  uint32_t nr_bf_per_box; // 1 -- 8
  uint32_t nr_index;
  uint64_t mtid;
  uint16_t *index_last;       // the LAST barrel_id in each box
};


#define NR_SEGMENTS 4
#define NR_SEGMENTS_MAX ((NR_SEGMENTS * 4))
#define NR_BFS_PER_SEGMENT (32)

struct SegmentBloomContainer {
  int raw_fd;
  uint32_t nr_bf;
  uint32_t cur_segment;
  uint32_t need_discard_segment;
  uint32_t nr_barrels;    // === nr_main
  uint64_t max_box_len[NR_SEGMENTS_MAX];
  uint16_t container_unit_count[NR_SEGMENTS_MAX];
  uint64_t off_raw[NR_SEGMENTS_MAX][NR_PAGES_BF_MAX];       // === off_main in MetaFileHeader
  uint16_t nr_bf_per_box[NR_SEGMENTS_MAX]; // 1 -- 8
  uint32_t nr_index[NR_SEGMENTS_MAX];
  uint64_t mtid;
  uint16_t *index_last[NR_SEGMENTS_MAX];       // the LAST barrel_id in each box
};

struct BloomFilter *
bloom_create(const uint32_t nr_keys, struct Mempool * const mempool);

void
bloom_update(struct BloomFilter * const bf, const uint64_t hv);

bool
bloom_match(const struct BloomFilter * const bf, const uint64_t hv);

struct BloomFilterGroup *
bloom_create_update(const uint32_t nr_keys, const int64_t* hvs, struct Mempool * const mempool);

  bool
bloom_group_match(const struct BloomFilterGroup * const bf, const uint64_t hv);

// for original BloomTable
struct BloomTable *
bloomtable_build(struct BloomFilter * const * const bfs, const uint64_t nr_bf);

bool
bloomtable_dump(struct BloomTable * const bt, FILE *fo);

struct BloomTable *
bloomtable_load(FILE * const fi);

bool
bloomtable_match(struct BloomTable * const bt, const uint32_t index, const uint64_t hv);

void
bloomtable_free(struct BloomTable * const bt);

// for BloomGroupTable
  struct BloomGroupTable *
bloomgrouptable_build(struct BloomFilterGroup * const * const bfs, const uint64_t nr_bf);

bool
bloomgrouptable_dump(struct BloomGroupTable * const bt, FILE *fo);

struct BloomGroupTable *
bloomgrouptable_load(FILE * const fi);

bool
bloomgrouptable_match(struct BloomGroupTable * const bt, const uint32_t index, const uint64_t hv);

void
bloomgrouptable_free(struct BloomGroupTable * const bt);

// for original BloomContainer
struct BloomContainer *
bloomcontainer_build(struct BloomTable * const bt, const int raw_fd,
    const uint64_t off_raw, struct Stat * const stat);

  struct BloomContainer *
bloomcontainer_update(struct ContainerMap * const cm, struct BloomContainer * const bc, 
  struct BloomTable * bt, struct Stat * const stat);

bool
bloomcontainer_dump_meta(struct BloomContainer * const bc, FILE * const fo);

struct BloomContainer *
bloomcontainer_load_meta(FILE * const fi, const int raw_fd);

uint64_t
bloomcontainer_match(struct BloomContainer * const bc, const uint32_t index, const uint64_t hv, uint8_t *ret);

void
bloomcontainer_free(struct BloomContainer *const bc);

// for SegmentBloomContainer
  struct SegmentBloomContainer *
segmentbloomcontainer_build(struct ContainerMap * const cm, struct SegmentBloomContainer * const bc_old, 
  struct BloomGroupTable * bts[32], const int bt_count, struct Stat * const stat);

  struct SegmentBloomContainer *
segmentbloomcontainer_update(struct ContainerMap * const cm, struct SegmentBloomContainer * const bc, 
  struct BloomGroupTable * bts[32], const int bt_count, struct Stat * const stat);

bool
segmentbloomcontainer_dump_meta(struct SegmentBloomContainer * const bc, FILE * const fo);

struct SegmentBloomContainer *
segmentbloomcontainer_load_meta(FILE * const fi, const int raw_fd);

uint32_t
segmentbloomcontainer_match(struct SegmentBloomContainer * const bc, const uint32_t index, const uint64_t hv, uint8_t *ret);

void
segmentbloomcontainer_free(struct SegmentBloomContainer *const bc);
