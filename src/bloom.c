/*
 * Copyright (c) 2014  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coding.h"
#include "table.h"
#include "mempool.h"
#include "coding.h"
#include "stat.h"

#include "bloom.h"
// 20-14
// 18-12 * 2.5 ~ 5
// 16-11 * x8 0.05%  x64 ~3%  x128 ~6%
// 14-10
// 12-8
// 10-7  * x8 6%~7%  x64 ~40% x128 ~64%

#define BITS_PER_KEY ((16))
#define NR_PROBES ((11))

#define HSHIFT0 ((31))
#define HSHIFT1 ((64 - HSHIFT0))

// #define USE_BLOCK_FILTER
#define get16bits(d) (*((const uint16_t *)(d)))

uint32_t SuperFastHash(const uint64_t k) {
  const char *data = (const char *) (&k);
  size_t len = sizeof(uint64_t);
  uint32_t hash = len, tmp;
  int rem;

  if (len <= 0 || data == NULL) return 0;

  rem = len & 3;
  len >>= 2;

  /* Main loop */
  for (; len > 0; len--) {
    hash += get16bits(data);
    tmp = (get16bits(data + 2) << 11) ^ hash;
    hash = (hash << 16) ^ tmp;
    data += 2 * sizeof(uint16_t);
    hash += hash >> 11;
  }

  /* Handle end cases */
  switch (rem) {
    case 3:
      hash += get16bits(data);
      hash ^= hash << 16;
      hash ^= data[sizeof(uint16_t)] << 18;
      hash += hash >> 11;
      break;
    case 2:
      hash += get16bits(data);
      hash ^= hash << 11;
      hash += hash >> 17;
      break;
    case 1:
      hash += *data;
      hash ^= hash << 10;
      hash += hash >> 1;
  }

  /* Force "avalanching" of final 127 bits */
  hash ^= hash << 3;
  hash += hash >> 5;
  hash ^= hash << 4;
  hash += hash >> 17;
  hash ^= hash << 25;
  hash += hash >> 6;

  return hash;
}

  static inline uint64_t
bloom_bytes_to_bits(const uint32_t len)
{
  // make it odd
  return (len << 3) - 3;
}

  struct BloomFilter *
bloom_create(const uint32_t nr_keys, struct Mempool * const mempool)
{
  uint32_t bytes0 = (nr_keys * BITS_PER_KEY + 7) >> 3;
  uint32_t bytes = (bytes0 < 8u)?8u:bytes0; // align

static int flag = 0;
#ifdef USE_BLOCK_FILTER
  if (flag++ == 0) {
    int partitionNum = NR_PARTITIONS;
    printf("use blocked filter, partition num %d\n", partitionNum);
  }
  bytes0 = (nr_keys * BITS_PER_KEY + NR_PARTITIONS - 1) / NR_PARTITIONS;
  bytes0 *= NR_PARTITIONS;
  bytes0 = (bytes0 + 7) >> 3;
  bytes = (bytes0 < 8u)?8u:bytes0;
#else
    if (flag++ == 0)
      printf("use normal filter\n");
#endif

  struct BloomFilter *const bf = (typeof(bf))mempool_alloc(mempool, sizeof(*bf) + bytes);
  bf->bytes = bytes;
  bf->nr_keys = 0;
  bzero(bf->filter, bytes);
  return bf;
}

  void
bloom_update(struct BloomFilter * const bf, const uint64_t hv)
{
  uint64_t h = hv;
  const uint64_t delta = (h >> HSHIFT0) | (h << HSHIFT1);
  uint64_t bits = bloom_bytes_to_bits(bf->bytes);

#ifndef USE_BLOCK_FILTER
  for (uint32_t j = 0u; j < NR_PROBES; j++) {
    const uint64_t bitpos = h % bits;
    bf->filter[bitpos>>3u] |= (1u << (bitpos % 8u));
    h += delta;
    h = SuperFastHash(h);
  }
#else
  h = SuperFastHash(h);
  uint32_t partition = h % NR_PARTITIONS;
  bits = (bf->bytes * 8u) / NR_PARTITIONS;
  for (uint32_t j = 0u; j < NR_PROBES; j++) {
    h += delta;
    h = SuperFastHash(h);
    const uint64_t bitpos = h % bits + partition * bits;
    bf->filter[bitpos>>3u] |= (1u << (bitpos % 8u));
  }
#endif

  bf->nr_keys++;
}

struct BloomFilterGroup *
bloom_create_update(const uint32_t nr_keys, const int64_t* hvs, struct Mempool * const mempool) {
  uint64_t par_keys[NR_PARTITIONS] = {0};
  uint64_t par_hvs[NR_PARTITIONS][512] = {0};
  struct BloomFilterGroup *bfs = (typeof(bfs))mempool_alloc(mempool, sizeof(*bfs));

  for (uint32_t i = 0; i < nr_keys; i++) {
    uint32_t pid = SuperFastHash(hvs[i]) % NR_PARTITIONS;
    par_hvs[pid][par_keys[pid]] = hvs[i];
    par_keys[pid] += 1;
  }

  uint32_t avg_bytes = ((nr_keys * BITS_PER_KEY + 7) >> 3) / NR_PARTITIONS;

  for (uint32_t p = 0; p < NR_PARTITIONS; p++) {
    uint32_t bytes0 = (par_keys[p] * BITS_PER_KEY + 7) >> 3;
    uint32_t bytes = (bytes0 < 8u)?8u:bytes0; // align
    if (bytes < avg_bytes) {
      bytes = avg_bytes;
    }
    struct BloomFilter *const bf = (typeof(bf))mempool_alloc(mempool, sizeof(*bf) + bytes);
    bf->bytes = bytes;
    bf->nr_keys = 0;
    bfs->group[p] = bf;
    bzero(bf->filter, bytes);
    for (uint32_t i = 0; i < par_keys[p]; i++) {
      uint64_t h = par_hvs[p][i];
      const uint64_t delta = (h >> HSHIFT0) | (h << HSHIFT1);
      uint64_t bits = bloom_bytes_to_bits(bf->bytes);
      for (uint32_t j = 0u; j < NR_PROBES; j++) {
        const uint64_t bitpos = h % bits;
        bf->filter[bitpos>>3u] |= (1u << (bitpos % 8u));
        h += delta;
        h = SuperFastHash(h);
      }
    }
  }

  return bfs;
}

  static inline bool
bloom_match_raw(const uint8_t *const filter, const uint32_t bytes, const uint64_t hv)
{
  uint64_t h = hv;
  const uint64_t delta = (h >> HSHIFT0) | (h << HSHIFT1);
  uint64_t bits = bloom_bytes_to_bits(bytes);
#ifndef USE_BLOCK_FILTER
  for (uint32_t j = 0u; j < NR_PROBES; j++) {
    const uint64_t bitpos = h % bits;
    if ((filter[bitpos>>3u] & (1u << (bitpos % 8u))) == 0u) return false;
    h += delta;
    h = SuperFastHash(h);
  }
#else
  h = SuperFastHash(h);
  uint32_t partition = h % NR_PARTITIONS;
  bits = (bytes * 8u) / NR_PARTITIONS;
  for (uint32_t j = 0u; j < NR_PROBES; j++) {
    h += delta;
    h = SuperFastHash(h);
    const uint64_t bitpos = h % bits + partition * bits;
    if ((filter[bitpos>>3u] & (1u << (bitpos % 8u))) == 0u) return false;
  }
#endif
  return true;
}

  bool
bloom_match(const struct BloomFilter * const bf, const uint64_t hv)
{
  return bloom_match_raw(bf->filter, bf->bytes, hv);
}

  bool
bloom_group_match(const struct BloomFilterGroup * const bf, const uint64_t hv)
{
  uint32_t pid = SuperFastHash(hv) % NR_PARTITIONS;
  return bloom_match(bf->group[pid], hv);
}

// format: <length> <raw_bf> <length> <raw_bf> ...
// bloomtable is used independently to the table, so don't use mempool
  struct BloomTable *
bloomtable_build(struct BloomFilter * const * const bfs, const uint64_t nr_bf)
{
  const uint64_t nr_offsets = (nr_bf + BLOOMTABLE_INTERVAL - 1u) / BLOOMTABLE_INTERVAL;
  struct BloomTable * const bt = (typeof(bt))malloc(sizeof(*bt) + (nr_offsets * sizeof(bt->offsets[0])));
  assert(bt);
  uint32_t all_bytes = 0;
  uint8_t buf[20];

  // counting bytes
  for (uint64_t i = 0; i < nr_bf; i++) {
    struct BloomFilter * const bf = bfs[i];
    const uint8_t * p = encode_uint64(buf, bf->bytes);
    const uint32_t bytes = p + bf->bytes - buf;
    all_bytes += bytes;
  }
  bt->nr_bytes = all_bytes;

  //
  uint8_t * const raw_bf = (typeof(raw_bf))malloc(all_bytes + 8u);
  assert(raw_bf);
  uint8_t * ptr = raw_bf;
  for (uint64_t i = 0; i < nr_bf; i++) {
    if ((i % BLOOMTABLE_INTERVAL) == 0) {
      bt->offsets[i/BLOOMTABLE_INTERVAL] = (ptr - raw_bf);
    }
    struct BloomFilter * const bf = bfs[i];
    uint8_t * const pfilter = encode_uint64(ptr, bf->bytes);
    memcpy(pfilter, bf->filter, bf->bytes);
    ptr = pfilter + bf->bytes;
  }
  assert(nr_bf < UINT64_C(0x100000000));
  bt->nr_bf = (typeof(bt->nr_bf))nr_bf;
  bt->raw_bf = raw_bf;
  return bt;
}

// format: <length> <raw_bf> <length> <raw_bf> ...
// bloomtable is used independently to the table, so don't use mempool
  struct BloomGroupTable *
bloomgrouptable_build(struct BloomFilterGroup * const * const bfs, const uint64_t nr_bf)
{
  const uint64_t nr_offsets = (nr_bf + BLOOMTABLE_INTERVAL - 1u) / BLOOMTABLE_INTERVAL;
  struct BloomGroupTable * const bt = (typeof(bt))malloc(sizeof(*bt)); // + (nr_offsets * sizeof(bt->offsets[0]))
  assert(bt);
  uint32_t all_bytes = 0;
  uint8_t buf[20];

  for (uint32_t p = 0; p < NR_PARTITIONS; p++) {
    bt->offsets[p] = (typeof(bt->offsets[p])) malloc(nr_offsets * sizeof(uint32_t));

    // counting bytes
    for (uint64_t i = 0; i < nr_bf; i++) {
      struct BloomFilter * const bf = bfs[i]->group[p];
      const uint8_t * p = encode_uint64(buf, bf->bytes);
      const uint32_t bytes = p + bf->bytes - buf;
      all_bytes += bytes;
    }
  }
  bt->nr_bytes = all_bytes;
  uint8_t * const raw_bf = (typeof(raw_bf))malloc(all_bytes + 8u);
  assert(raw_bf);
  uint8_t * ptr = raw_bf;
  assert(nr_bf < UINT64_C(0x100000000));
  bt->nr_bf = (typeof(bt->nr_bf))nr_bf;
  bt->raw_bf = raw_bf;

  for (uint32_t p = 0; p < NR_PARTITIONS; p++) {
    for (uint64_t i = 0; i < nr_bf; i++) {
      if ((i % BLOOMTABLE_INTERVAL) == 0) {
        bt->offsets[p][i/BLOOMTABLE_INTERVAL] = (ptr - raw_bf);
      }
      struct BloomFilter * const bf = bfs[i]->group[p];
      uint8_t * const pfilter = encode_uint64(ptr, bf->bytes);
      memcpy(pfilter, bf->filter, bf->bytes);
      ptr = pfilter + bf->bytes;
    }
  }

  return bt;
}

  bool
bloomtable_dump(struct BloomTable * const bt, FILE * const fo)
{
  assert(bt);
  const size_t nb = fwrite(&(bt->nr_bytes), sizeof(bt->nr_bytes), 1, fo);
  assert(nb == 1);

  const size_t nr_btbytes = bt->nr_bytes;
  const size_t nw = fwrite(bt->raw_bf, sizeof(bt->raw_bf[0]), nr_btbytes, fo);
  assert(nw == nr_btbytes);
  return true;
}

  bool
bloomgrouptable_dump(struct BloomGroupTable * const bt, FILE * const fo)
{
  assert(bt);
  const size_t nb = fwrite(&(bt->nr_bytes), sizeof(bt->nr_bytes), 1, fo);
  assert(nb == 1);

  const size_t nbf = fwrite(&(bt->nr_bf), sizeof(bt->nr_bf), 1, fo);
  assert(nbf == 1);

  const size_t nr_btbytes = bt->nr_bytes;
  const size_t nw = fwrite(bt->raw_bf, sizeof(bt->raw_bf[0]), nr_btbytes, fo);
  assert(nw == nr_btbytes);
  return true;
}

  struct BloomTable *
bloomtable_load(FILE * const fi)
{
  // assuming fi have been seeked to correct offset
  uint32_t raw_size;
  const size_t ns = fread(&raw_size, sizeof(raw_size), 1, fi);
  assert(ns == 1);

  uint8_t * const raw_bf = (typeof(raw_bf))malloc(raw_size + 8);
  assert(raw_bf);
  const size_t nr = fread(raw_bf, sizeof(raw_bf[0]), raw_size, fi);
  assert(nr == raw_size);
  // scan and generate interval index
  uint32_t offsets[TABLE_MAX_BARRELS/BLOOMTABLE_INTERVAL];
  uint32_t nr_offsets = 0u;
  const uint8_t *ptr = raw_bf;
  uint32_t i = 0u;
  while(ptr - raw_bf < raw_size) {
    uint64_t bf_len;
    const uint8_t *praw = decode_uint64(ptr, &bf_len);
    assert(praw > ptr);
    assert(bf_len);
    if ((i % BLOOMTABLE_INTERVAL) == 0u) {
      offsets[i/BLOOMTABLE_INTERVAL] = (ptr - raw_bf);
      nr_offsets++;
    }
    i++;
    ptr = praw + bf_len;
  }
  const uint32_t nr_bf = i;
  assert(ptr == (raw_bf + raw_size));

  struct BloomTable * const bt = (typeof(bt))malloc(sizeof(*bt) + (nr_offsets * sizeof(bt->offsets[0])));
  assert(bt);
  bt->raw_bf = raw_bf;
  bt->nr_bf = nr_bf;
  bt->nr_bytes = raw_size;
  memcpy(bt->offsets, offsets, sizeof(offsets[0]) * nr_offsets);
  return bt;
}

  struct BloomGroupTable *
bloomgrouptable_load(FILE * const fi)
{
  // assuming fi have been seeked to correct offset
  uint32_t raw_size;
  const size_t ns = fread(&raw_size, sizeof(raw_size), 1, fi);
  assert(ns == 1);

  uint32_t nr_bf;
  const size_t nbf = fread(&nr_bf, sizeof(nr_bf), 1, fi);
  assert(nbf == 1);

  uint8_t * const raw_bf = (typeof(raw_bf))malloc(raw_size + 8);
  assert(raw_bf);
  const size_t nr = fread(raw_bf, sizeof(raw_bf[0]), raw_size, fi);
  assert(nr == raw_size);

  struct BloomGroupTable * const bt = (typeof(bt))malloc(sizeof(*bt));
  assert(bt);
  bt->raw_bf = raw_bf;
  bt->nr_bf = nr_bf;
  bt->nr_bytes = raw_size;

  const uint8_t *ptr = raw_bf;
  for (uint32_t p = 0; p < NR_PARTITIONS; p++) {
    // scan and generate interval index
    uint32_t offsets[TABLE_MAX_BARRELS/BLOOMTABLE_INTERVAL];
    uint32_t nr_offsets = 0u;
    for (uint32_t i = 0; i < nr_bf; i++) {
      uint64_t bf_len;
      const uint8_t *praw = decode_uint64(ptr, &bf_len);
      assert(praw > ptr);
      assert(bf_len);
      if ((i % BLOOMTABLE_INTERVAL) == 0u) {
        offsets[i/BLOOMTABLE_INTERVAL] = (ptr - raw_bf);
        nr_offsets++;
      }
      ptr = praw + bf_len;
    }
    bt->offsets[p] = (typeof(bt->offsets[p])) malloc(nr_offsets * sizeof(uint32_t));
    memcpy(bt->offsets[p], offsets, sizeof(offsets[0]) * nr_offsets);
  }
  assert(ptr == (raw_bf + raw_size));

  return bt;
}

  bool
bloomtable_match(struct BloomTable * const bt, const uint32_t index, const uint64_t hv)
{
  // find the raw filter
  assert(index < bt->nr_bf);
  const uint32_t ixix = index / BLOOMTABLE_INTERVAL;
  const uint8_t * ptr = &(bt->raw_bf[bt->offsets[ixix]]);
  for (uint32_t i = ixix * BLOOMTABLE_INTERVAL; i < index; i++) {
    uint64_t bf_len;
    const uint8_t * const pbf = decode_uint64(ptr, &bf_len);
    assert(pbf > ptr);
    assert(bf_len);
    ptr = pbf + bf_len;
  }

  // get bytes
  uint32_t bytes;
  const uint8_t * const pbf = decode_uint32(ptr, &bytes);
  assert(pbf > ptr);
  assert(bytes);

  return bloom_match_raw(pbf, bytes, hv);
}

  bool
bloomgrouptable_match(struct BloomGroupTable * const bt, const uint32_t index, const uint64_t hv)
{
  uint32_t p = SuperFastHash(hv) % NR_PARTITIONS;

  // find the raw filter
  assert(index < bt->nr_bf);
  const uint32_t ixix = index / BLOOMTABLE_INTERVAL;
  const uint8_t * ptr = &(bt->raw_bf[bt->offsets[p][ixix]]);
  for (uint32_t i = ixix * BLOOMTABLE_INTERVAL; i < index; i++) {
    uint64_t bf_len;
    const uint8_t * const pbf = decode_uint64(ptr, &bf_len);
    assert(pbf > ptr);
    assert(bf_len);
    ptr = pbf + bf_len;
  }

  // get bytes
  uint32_t bytes;
  const uint8_t * const pbf = decode_uint32(ptr, &bytes);
  assert(pbf > ptr);
  assert(bytes);

  return bloom_match_raw(pbf, bytes, hv);
}

  void
bloomtable_free(struct BloomTable * const bt)
{
  if (bt->raw_bf) {
    free(bt->raw_bf);
  }
  free(bt);
}

  void
bloomgrouptable_free(struct BloomGroupTable * const bt)
{
  if (bt->raw_bf) {
    free(bt->raw_bf);
  }
  for (uint32_t p = 0; p < NR_PARTITIONS; p++) {
    free(bt->offsets[p]);
  }
  free(bt);
}

//         uint16_t uint16_t     encoded
// format: <box-id> <len-of-box> <len-of-bf> <raw_bf> <len-of-bf> <raw_bf> ...
  struct BloomContainer *
bloomcontainer_build(struct BloomTable * const bt, const int raw_fd,
    const uint64_t off_raw, struct Stat * const stat)
{
  const uint64_t pages_cap = TABLE_ALIGN;
  uint8_t *const pages = huge_alloc(pages_cap);
  assert(pages);

  uint8_t *page = pages;
  uint16_t index_last[TABLE_MAX_BARRELS] = {0};

  uint64_t current_page = 0;
  uint64_t off_page = 0;
  const uint8_t *ptr_bt = bt->raw_bf;
  assert(bt->nr_bf < 0x10000u);
  for (uint64_t i = 0; i < bt->nr_bf; i++) {
    // get new bf
    uint64_t bf_len;
    const uint8_t *const praw = decode_uint64(ptr_bt, &bf_len);
    assert(praw > ptr_bt);
    assert(bf_len);
    const uint64_t item_len = praw + bf_len - ptr_bt;

    // for new box
    const uint64_t boxlen_new = item_len;
    const uint64_t alllen_new = sizeof(uint16_t) + sizeof(uint16_t) + boxlen_new;
    // switch to next page
    if (off_page + alllen_new > BARREL_ALIGN) {
      if (off_page < BARREL_ALIGN) {
        bzero(page + off_page, BARREL_ALIGN - off_page);
      }
      page += BARREL_ALIGN;
      index_last[current_page] = i - 1;
      assert(alllen_new <= BARREL_ALIGN);
      // next page
      current_page++;
      off_page = 0;
    }

    // write box
    uint16_t *const pboxid_new = (typeof(pboxid_new))(page + off_page);
    *pboxid_new = (uint16_t)i;
    uint16_t *const pboxlen_new = (typeof(pboxlen_new))(page + off_page + sizeof(*pboxid_new));
    *pboxlen_new = boxlen_new;
    uint8_t * const pbox_new = page + off_page + sizeof(*pboxid_new) + sizeof(*pboxlen_new);

    // write new item first
    memcpy(pbox_new, ptr_bt, item_len);

    ptr_bt += item_len;
    off_page += alllen_new;
  }
  if (off_page < BARREL_ALIGN) {
    bzero(page + off_page, BARREL_ALIGN - off_page);
  }
  index_last[current_page] = bt->nr_bf - 1;
  current_page++;

  // write container
  const ssize_t nr_raw_bytes = (typeof(nr_raw_bytes))(current_page * BARREL_ALIGN);
  const ssize_t nrb = pwrite(raw_fd, pages, nr_raw_bytes, off_raw);
  assert(nrb == nr_raw_bytes);
  huge_free(pages, pages_cap);
  stat_inc_n(&(stat->nr_write_bc), current_page);

  // alloc new bc
  const uint64_t size_bc = sizeof(struct BloomContainer);
  struct BloomContainer *const bc = (typeof(bc))malloc(size_bc);
  assert(bc);
  bc->raw_fd = raw_fd;
  bc->container_unit_count = 1;
  bc->off_raw[0] = off_raw;
  bc->nr_barrels = bt->nr_bf;
  bc->nr_bf_per_box = 1;
  bc->nr_index = current_page;
  bc->index_last = (typeof(bc->index_last))malloc(sizeof(index_last[0]) * current_page);
  memcpy(bc->index_last, index_last, sizeof(index_last[0]) * current_page);
  return bc;
}

//         uint16_t uint16_t     encoded
// format: <box-id> <len-of-box> <len-of-bf> <raw_bf> <len-of-bf> <raw_bf> ...
  struct SegmentBloomContainer *
segmentbloomcontainer_build(struct ContainerMap * const cm, struct SegmentBloomContainer * const bc_old, 
  struct BloomGroupTable * bts[32], const int bt_count, struct Stat * const stat)
{
  const uint64_t pages_cap = TABLE_ALIGN;
  uint8_t *const pages = huge_alloc(pages_cap);
  assert(pages);

  uint8_t *page = pages;
  uint16_t index_last[TABLE_MAX_BARRELS * NR_PARTITIONS] = {0};

  uint64_t max_box_len = 0;

  uint64_t current_page = 0;
  uint64_t off_page = 0;
  uint8_t *ptr_bt[512];
  uint64_t item_len_p[512];
  assert(bt_count < 512);

  for (uint64_t j = bt_count; j--;) {
    struct BloomGroupTable * bt = bts[j];
    ptr_bt[j] = bt->raw_bf;
  }
// fprintf(stderr, "page %lu:", current_page);
  for (uint64_t p = 0; p < NR_PARTITIONS; p++) {

    for (uint64_t i = 0; i < TABLE_MAX_BARRELS; i++) {

      uint64_t item_len = 0;
      for (uint64_t j = bt_count; j--;) {
        // get new bf
        uint64_t bf_len;
        const uint8_t *const praw = decode_uint64(ptr_bt[j], &bf_len);
        assert(praw > ptr_bt[j]);
        assert(bf_len);
        item_len_p[j] = praw + bf_len - ptr_bt[j];
        item_len += item_len_p[j];
      }

      // for new box
      const uint64_t boxlen_new = item_len;
      const uint64_t alllen_new = sizeof(uint16_t) + sizeof(uint16_t) + boxlen_new;

      max_box_len = max_box_len < alllen_new ? alllen_new : max_box_len;
      
      // switch to next page
      if (off_page + alllen_new > BARREL_ALIGN) {
        if (off_page < BARREL_ALIGN) {
          bzero(page + off_page, BARREL_ALIGN - off_page);
        }
        page += BARREL_ALIGN;
        index_last[current_page] = i - 1 + p * TABLE_MAX_BARRELS;
        assert(alllen_new <= BARREL_ALIGN);
        // next page
        current_page++;
        off_page = 0;
  // fprintf(stderr, "\npage %lu:", current_page);
      }

      // write box
      uint16_t *const pboxid_new = (typeof(pboxid_new))(page + off_page);
      *pboxid_new = (uint16_t)i;
      uint16_t *const pboxlen_new = (typeof(pboxlen_new))(page + off_page + sizeof(*pboxid_new));
      *pboxlen_new = boxlen_new;
      uint8_t * pbox_new = page + off_page + sizeof(*pboxid_new) + sizeof(*pboxlen_new);
// fprintf(stderr, " id %u,len %u,", (uint32_t)*pboxid_new, (uint32_t)*pboxlen_new);

      for (uint64_t j = bt_count; j--;) {
        // write new item first
        memcpy(pbox_new, ptr_bt[j], item_len_p[j]);
        ptr_bt[j] += item_len_p[j];
        pbox_new += item_len_p[j];
// fprintf(stderr, "(b%lu,len%lu)", j, item_len_p[j]);
      }
      off_page += alllen_new;
    }
    if (off_page < BARREL_ALIGN) {
      bzero(page + off_page, BARREL_ALIGN - off_page);
    }
    page += BARREL_ALIGN;
    index_last[current_page] = TABLE_MAX_BARRELS - 1 + p * TABLE_MAX_BARRELS;
    current_page++;
    off_page = 0;
  }

  const uint64_t off_raw = containermap_alloc(cm);
  assert(off_raw < cm->total_cap);

  // write container
  const ssize_t nr_raw_bytes = (typeof(nr_raw_bytes))(current_page * BARREL_ALIGN);
  const ssize_t nrb = pwrite(cm->raw_fd, pages, nr_raw_bytes, off_raw);
  assert(nrb == nr_raw_bytes);
  huge_free(pages, pages_cap);
  stat_inc_n(&(stat->nr_write_bc), current_page);

  struct SegmentBloomContainer *bc;
  // alloc new bc
  const uint64_t size_bc = sizeof(struct SegmentBloomContainer);
  bc = (typeof(bc))malloc(size_bc);
  assert(bc);
  bzero(bc, size_bc);
  if (bc_old != NULL) {
    bc->nr_bf = bc_old->nr_bf;
    bc->cur_segment = bc_old->cur_segment;
    bc_old->need_discard_segment = bc_old->cur_segment + 1;
    for (uint64_t i = 0; i < bc_old->cur_segment; i++) {
      bc->container_unit_count[i] = bc_old->container_unit_count[i];
      memcpy(bc->off_raw[i], bc_old->off_raw[i], sizeof(bc->off_raw[i][0]) * NR_PAGES_BF_MAX);
      bc->max_box_len[i] = bc_old->max_box_len[i];
      bc->nr_bf_per_box[i] = bc_old->nr_bf_per_box[i];
      bc->nr_index[i] = bc_old->nr_index[i];
      bc->index_last[i] = (typeof(bc->index_last[i]))malloc(sizeof(index_last[0]) * bc->nr_index[i]);
      memcpy(bc->index_last[i], bc_old->index_last[i], sizeof(index_last[0]) * bc->nr_index[i]);
    }
  }

  bc->raw_fd = cm->raw_fd;
  bc->nr_bf += bt_count;
  bc->nr_barrels = TABLE_MAX_BARRELS;
  bc->container_unit_count[bc->cur_segment] = 1;
  bc->off_raw[bc->cur_segment][0] = off_raw;
  bc->max_box_len[bc->cur_segment] = max_box_len;
  bc->nr_bf_per_box[bc->cur_segment] = bt_count;
  bc->nr_index[bc->cur_segment] = current_page;
  bc->index_last[bc->cur_segment] = (typeof(bc->index_last[bc->cur_segment]))malloc(sizeof(index_last[0]) * current_page);
  memcpy(bc->index_last[bc->cur_segment], index_last, sizeof(index_last[0]) * current_page);

  return bc;
}

  struct BloomContainer *
bloomcontainer_update(struct ContainerMap * const cm, struct BloomContainer * const bc, 
  struct BloomTable * bt, struct Stat * const stat)
{
  uint16_t index_last[TABLE_MAX_BARRELS * 16] = {0};
  uint64_t current_page = 0;
  uint64_t off_page = 0;

  const int bt_count = 1;

  uint8_t *ptr_bt[512];
  uint64_t item_len_p[512];
  assert(bt_count < 512);

  const int max_segments = 1;

  //bf merge strategy
  uint32_t nr_merged_segment;
  uint32_t merged_segment[max_segments];
  uint64_t old_page[max_segments] = {};
  uint8_t old[BARREL_ALIGN * max_segments] __attribute__((aligned(4096)));
  uint8_t * ptr_old[max_segments];

  nr_merged_segment = 1;
  merged_segment[0] = 0;

  uint64_t new_bc_size = 0;
  for (uint64_t j = bt_count; j--;) {
    ptr_bt[j] = bt->raw_bf;
    new_bc_size += bt->nr_bytes;
  }
  for (uint64_t s = nr_merged_segment; s--;) {
    new_bc_size += bc->nr_index * BARREL_ALIGN;
  }
  uint64_t pages_cap = new_bc_size * 2 < TABLE_ALIGN ? TABLE_ALIGN : new_bc_size * 2;

  pages_cap = ((pages_cap + TABLE_ALIGN - 1) / TABLE_ALIGN) * TABLE_ALIGN;
  uint8_t *const pages = huge_alloc(pages_cap);
  // uint8_t *const pages = slab_alloc(slab, pages_cap);
  assert(pages);

  uint8_t *page = pages;

// fprintf(stderr, "page %lu:", current_page);

  const int NR_BF_PARTITIONS = 1;

  for (uint64_t p = 0; p < NR_BF_PARTITIONS; p++) {
    // load first old page -> old[]
    for (uint64_t s = nr_merged_segment; s--;) {
      uint32_t cur_segment = merged_segment[s];
      if (p != 0)
        old_page[s]++;

      if (old_page[s] % (bc->nr_index / NR_BF_PARTITIONS) != 0) {
        fprintf(stderr, "filter compaction update error!\n");
        exit(1);
      }

      ssize_t offset = old_page[s] * BARREL_ALIGN;
      const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
      assert(nbi == ((ssize_t)BARREL_ALIGN));
      ptr_old[s] = old + BARREL_ALIGN * s;
    }


    for (uint64_t i = 0; i < bt->nr_bf; i++) {
      
      uint64_t item_len = 0;
      for (uint64_t j = bt_count; j--;) {    
        // get new bf
        uint64_t bf_len;
        const uint8_t *const praw = decode_uint64(ptr_bt[j], &bf_len);
        assert(praw > ptr_bt[j]);
        assert(bf_len);
        item_len_p[j] = praw + bf_len - ptr_bt[j];
        assert(item_len_p[j] < 1024);
        item_len += item_len_p[j];
      }

      uint64_t boxlen_new = item_len;
      for (uint64_t s = nr_merged_segment; s--;) {
        // update old page buffer
        uint32_t cur_segment = merged_segment[s];
        uint32_t index_pages = bc->nr_index / NR_BF_PARTITIONS;
        if (i > bc->index_last[old_page[s] % index_pages]) {
          old_page[s]++;
          assert(i <= bc->index_last[old_page[s] % index_pages]);

          ssize_t offset = old_page[s] * BARREL_ALIGN;
          const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nbi == ((ssize_t)BARREL_ALIGN));
          ptr_old[s] = old + BARREL_ALIGN * s;
        }

        // get old box
        const uint16_t * const pboxid_old = (typeof(pboxid_old))ptr_old[s];
        const uint64_t boxid_old = (uint64_t)(*pboxid_old);
        assert(boxid_old == i);

        const uint16_t * const pboxlen_old = (typeof(pboxlen_old))(ptr_old[s] + sizeof(*pboxid_old));
        const uint64_t boxlen_old = (uint64_t)(*pboxlen_old);

        // for new box
        boxlen_new += boxlen_old;
      }
      int64_t alllen_new = sizeof(uint16_t) + sizeof(uint16_t) + boxlen_new;

      if (off_page != 0 && off_page + alllen_new > BARREL_ALIGN) { // switch to next page
        if (off_page < BARREL_ALIGN) {
          bzero(page + off_page, BARREL_ALIGN - off_page);
        }
        page += BARREL_ALIGN;
        off_page = 0;
        if (p == 0)
          index_last[current_page] = i - 1;
        // next page
        current_page++;
  // fprintf(stderr, "\npage %lu(actual %lu):", current_page, (page - pages) / BARREL_ALIGN);
        
      }

      // write box
      uint16_t *const pboxid_new = (typeof(pboxid_new))(page + off_page);
      *pboxid_new = (uint16_t)i;
      uint16_t *const pboxlen_new = (typeof(pboxlen_new))(page + off_page + sizeof(*pboxid_new));
      *pboxlen_new = boxlen_new;
      uint8_t * pbox_new = page + off_page + sizeof(*pboxid_new) + sizeof(*pboxlen_new);
// fprintf(stderr, "[%lu] id %lu,len %lu,", (uint64_t)(page - pages), (uint64_t)*pboxid_new, (uint64_t)*pboxlen_new);

      for (uint64_t j = bt_count; j--;) {
        // write new item first
        memcpy(pbox_new, ptr_bt[j], item_len_p[j]);
        ptr_bt[j] += item_len_p[j];
        pbox_new += item_len_p[j];
// fprintf(stderr, "(b%lu,len%lu)", j, item_len_p[j]);
      }
        // write old items
      for (uint64_t s = nr_merged_segment; s--;) {
        // update old page buffer
        uint32_t cur_segment = merged_segment[s];

        // get old box
        const uint16_t * const pboxid_old = (typeof(pboxid_old))ptr_old[s];
        const uint64_t boxid_old = (uint64_t)(*pboxid_old);
        assert(boxid_old == i);

        const uint16_t * const pboxlen_old = (typeof(pboxlen_old))(ptr_old[s] + sizeof(*pboxid_old));
        const uint64_t boxlen_old = (uint64_t)(*pboxlen_old);
        const uint8_t * pbox_old = ptr_old[s] + sizeof(*pboxid_old) + sizeof(*pboxlen_old);

        uint64_t alllen_old = sizeof(*pboxid_old) + sizeof(*pboxlen_old) + boxlen_old;

// fprintf(stderr, "(s%lu,len%lu)", cur_segment, boxlen_old);
        if (alllen_old <= BARREL_ALIGN){
          memcpy(pbox_new, pbox_old, boxlen_old);
          pbox_new += boxlen_old;
        }
        else {
          while (alllen_old > BARREL_ALIGN) {
            uint64_t copy_size = BARREL_ALIGN - (pbox_old - ptr_old[s]);
            memcpy(pbox_new, pbox_old, copy_size);
            pbox_new += copy_size;
            alllen_old -= BARREL_ALIGN;

            old_page[s]++;

            ssize_t offset = old_page[s] * BARREL_ALIGN;
            const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
            assert(nbi == ((ssize_t)BARREL_ALIGN));
            ptr_old[s] = old + BARREL_ALIGN * s;
            pbox_old = ptr_old[s];
          }
          memcpy(pbox_new, pbox_old, alllen_old);
          pbox_new += alllen_old;

        }

        ptr_old[s] += alllen_old;
      }

      if (alllen_new > BARREL_ALIGN) {
        while (alllen_new > 0) {
          alllen_new -= BARREL_ALIGN;
          page += BARREL_ALIGN;
          if (alllen_new < BARREL_ALIGN)
            bzero(page + alllen_new, BARREL_ALIGN - alllen_new);

          if (p == 0)
            index_last[current_page] = i;
          current_page++;
        }
      }
      else
        off_page += alllen_new;

    }
    if (off_page != 0) {
      bzero(page + off_page, BARREL_ALIGN - off_page);
      page += BARREL_ALIGN;
      off_page = 0;
      if (p == 0)
        index_last[current_page] = TABLE_NR_BARRELS - 1;
      current_page++;
    }
  }
// fprintf(stderr, "current_page %lu\n", current_page);
  assert(current_page % NR_BF_PARTITIONS == 0);
  if (current_page % NR_BF_PARTITIONS != 0) {
    fprintf(stderr, "filter compaction error!\n");
    exit(1);
  }

  // bloomcontainer_check(pages, current_page, bc->nr_bf_per_box[bc->cur_segment] + bt_count, index_last);

// fprintf(stderr, "pages_cap :%lu, current_page %lu\n", pages_cap, current_page * BARREL_ALIGN);

  uint32_t container_unit_count = 0;
  uint64_t off_raws[NR_PAGES_BF_MAX];
  int64_t nr_raw_bytes = (typeof(nr_raw_bytes))(current_page * BARREL_ALIGN);

  page = pages;
  while (nr_raw_bytes > 0) {
    const uint64_t off_raw = containermap_alloc(cm);
    assert(off_raw < cm->total_cap);
    const ssize_t write_size = TABLE_ALIGN > nr_raw_bytes ? nr_raw_bytes : TABLE_ALIGN;
    // write container
    const ssize_t nrb = pwrite(cm->raw_fd, page, write_size, off_raw);
    assert(nrb == write_size);
    
    off_raws[container_unit_count] = off_raw;
    page += write_size;
    nr_raw_bytes -= write_size;
    container_unit_count += 1;
  }

  huge_free(pages, pages_cap);
  // slab_free(slab, pages);
  stat_inc_n(&(stat->nr_write_bc), current_page);

  uint32_t nr_bf_per_box = bt_count;
  for (uint64_t s = nr_merged_segment; s--;) {
    uint32_t cur_segment = merged_segment[s];
    // fprintf(stderr, "merged_segment %u, nr_bf_per_box %u\n", cur_segment, bc->nr_bf_per_box[cur_segment]);
    nr_bf_per_box += bc->nr_bf_per_box;
  }
  // fprintf(stderr, "nr_bf_per_box %d\n", nr_bf_per_box);

  struct BloomContainer *bc_new;
  // alloc new bc
  const uint64_t size_bc = sizeof(struct BloomContainer);
  bc_new = (typeof(bc_new)) malloc(size_bc);
  assert(bc_new);
  bzero(bc_new, size_bc);

  for (uint64_t i = 0; i < current_page / NR_BF_PARTITIONS; i++)
    assert(index_last[i] < TABLE_NR_BARRELS);


  bc_new->raw_fd = cm->raw_fd;
  bc_new->nr_barrels = bc->nr_barrels;

  bc_new->container_unit_count = container_unit_count;
  for (uint64_t i = 0; i < container_unit_count; i++)
    bc_new->off_raw[i] = off_raws[i];

  bc_new->nr_bf_per_box = nr_bf_per_box; // ++
  bc_new->nr_index = current_page;
  bc_new->index_last = (typeof(bc_new->index_last))malloc(sizeof(index_last[0]) * current_page / NR_BF_PARTITIONS);
  memcpy(bc_new->index_last, index_last, sizeof(index_last[0]) * current_page / NR_BF_PARTITIONS);

  return bc_new;
}

uint32_t bit_count(uint64_t n) {
    uint32_t c;
    for (c = 0; n; ++c) {
        n &= (n - 1);
    }
    return c;
}

  struct SegmentBloomContainer *
segmentbloomcontainer_update(struct ContainerMap * const cm, struct SegmentBloomContainer * const bc, 
  struct BloomGroupTable * bts[32], const int bt_count, struct Stat * const stat)
{
  uint16_t index_last[TABLE_MAX_BARRELS * NR_PARTITIONS * 16] = {0};
  uint64_t current_page = 0;
  uint64_t off_page = 0;

  uint8_t *ptr_bt[512];
  uint64_t item_len_p[512];
  assert(bt_count < 512);


  //bf merge strategy
  uint32_t nr_merged_segment;
  uint32_t merged_segment[NR_SEGMENTS_MAX];
  uint64_t old_page[NR_SEGMENTS_MAX] = {};
  uint8_t old[BARREL_ALIGN * NR_SEGMENTS_MAX] __attribute__((aligned(4096)));
  uint8_t * ptr_old[NR_SEGMENTS_MAX];
  uint32_t cur_segment_new, cur_segment_post = 0;


  uint64_t max_box_len_post = bc->max_box_len[bc->cur_segment];
  for (uint64_t j = 0; j < bt_count; j++) {
    max_box_len_post += 1;// bts[j]->max_item_len;
  }

  // uint32_t nr_segment_pre = 0;
  // for (uint64_t j = 0; j <= bc->cur_segment; j++) {
  //   nr_segment_pre += bc->max_box_len[j];
  // }
  // nr_segment_pre = (uint32_t) (((double)nr_segment_pre) / BARREL_ALIGN + 0.5);
  uint32_t nr_segment_pre = (bc->nr_bf + bt_count) / NR_BFS_PER_SEGMENT;

  if (bc->nr_bf_per_box[bc->cur_segment] + bt_count >= NR_BFS_PER_SEGMENT) {
    uint32_t power = 0;
    uint32_t tmp = nr_segment_pre;
    while (tmp % 2 == 0){
      power += 1;
      tmp /= 2;
    }
    uint64_t segment_exists_bits = (1 << power) - 1;
 
    nr_merged_segment = bit_count(segment_exists_bits) + 1;
    for (uint32_t i = 0; i < nr_merged_segment; i++)
      merged_segment[i] = bc->cur_segment - nr_merged_segment + 1 + i;

    cur_segment_new = bc->cur_segment - nr_merged_segment + 1;
    assert(cur_segment_new >= 0);
    cur_segment_post = cur_segment_new + 1;
  }
  else {
    if (bc->nr_bf_per_box[bc->cur_segment] == 0)
      return segmentbloomcontainer_build(cm, bc, bts, bt_count, stat);

    nr_merged_segment = 1;
    merged_segment[0] = bc->cur_segment;
    cur_segment_new = bc->cur_segment;
    cur_segment_post = bc->cur_segment;
  }
  bc->need_discard_segment = cur_segment_new;

  uint64_t new_bc_size = 0;
  for (uint64_t j = bt_count; j--;) {
    struct BloomGroupTable * bt = bts[j];
    ptr_bt[j] = bt->raw_bf;
    new_bc_size += bt->nr_bytes;
  }
  for (uint64_t s = nr_merged_segment; s--;) {
    new_bc_size += bc->nr_index[merged_segment[s]] * BARREL_ALIGN;
  }
  uint64_t pages_cap = new_bc_size * 2 < TABLE_ALIGN ? TABLE_ALIGN : new_bc_size * 2;

  pages_cap = ((pages_cap + TABLE_ALIGN - 1) / TABLE_ALIGN) * TABLE_ALIGN;
  uint8_t *const pages = huge_alloc(pages_cap);
  // uint8_t *const pages = slab_alloc(slab, pages_cap);
  assert(pages);

  uint8_t *page = pages;

// fprintf(stderr, "page %lu:", current_page);

  uint64_t max_box_len = 0;

  for (uint64_t p = 0; p < NR_PARTITIONS; p++) {
    // load first old page -> old[]
    for (uint64_t s = nr_merged_segment; s--;) {
      uint32_t cur_segment = merged_segment[s];
      if (p != 0)
        old_page[s]++;

      ssize_t offset = old_page[s] * BARREL_ALIGN;
      const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
      assert(nbi == ((ssize_t)BARREL_ALIGN));
      ptr_old[s] = old + BARREL_ALIGN * s;
    }


    for (uint64_t i = 0; i < TABLE_MAX_BARRELS; i++) {
      
      uint64_t item_len = 0;
      for (uint64_t j = bt_count; j--;) {    
        // get new bf
        uint64_t bf_len;
        const uint8_t *const praw = decode_uint64(ptr_bt[j], &bf_len);
        assert(praw > ptr_bt[j]);
        assert(bf_len);
        item_len_p[j] = praw + bf_len - ptr_bt[j];
        assert(item_len_p[j] < 1024);
        item_len += item_len_p[j];
      }

      uint64_t boxlen_new = item_len;
      for (uint64_t s = nr_merged_segment; s--;) {
        // update old page buffer
        uint32_t cur_segment = merged_segment[s];
        if (i + p * TABLE_MAX_BARRELS > bc->index_last[cur_segment][old_page[s]]) {
          old_page[s]++;
          assert(i <= bc->index_last[cur_segment][old_page[s]]);

          ssize_t offset = old_page[s] * BARREL_ALIGN;
          const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nbi == ((ssize_t)BARREL_ALIGN));
          ptr_old[s] = old + BARREL_ALIGN * s;
        }

        // get old box
        const uint16_t * const pboxid_old = (typeof(pboxid_old))ptr_old[s];
        const uint64_t boxid_old = (uint64_t)(*pboxid_old);
        assert(boxid_old == i);

        const uint16_t * const pboxlen_old = (typeof(pboxlen_old))(ptr_old[s] + sizeof(*pboxid_old));
        const uint64_t boxlen_old = (uint64_t)(*pboxlen_old);

        // for new box
        boxlen_new += boxlen_old;
      }
      int64_t alllen_new = sizeof(uint16_t) + sizeof(uint16_t) + boxlen_new;

      max_box_len = max_box_len < alllen_new ? alllen_new : max_box_len;

      if (off_page != 0 && off_page + alllen_new > BARREL_ALIGN) { // switch to next page
        if (off_page < BARREL_ALIGN) {
          bzero(page + off_page, BARREL_ALIGN - off_page);
        }
        page += BARREL_ALIGN;
        off_page = 0;
        index_last[current_page] = i - 1 + p * TABLE_MAX_BARRELS;
        // next page
        current_page++;
  // fprintf(stderr, "\npage %lu(actual %lu):", current_page, (page - pages) / BARREL_ALIGN);
        
      }

      // write box
      uint16_t *const pboxid_new = (typeof(pboxid_new))(page + off_page);
      *pboxid_new = (uint16_t)i;
      uint16_t *const pboxlen_new = (typeof(pboxlen_new))(page + off_page + sizeof(*pboxid_new));
      *pboxlen_new = boxlen_new;
      uint8_t * pbox_new = page + off_page + sizeof(*pboxid_new) + sizeof(*pboxlen_new);
// fprintf(stderr, "[%lu] id %lu,len %lu,", (uint64_t)(page - pages), (uint64_t)*pboxid_new, (uint64_t)*pboxlen_new);

      for (uint64_t j = bt_count; j--;) {
        // write new item first
        memcpy(pbox_new, ptr_bt[j], item_len_p[j]);
        ptr_bt[j] += item_len_p[j];
        pbox_new += item_len_p[j];
// fprintf(stderr, "(b%lu,len%lu)", j, item_len_p[j]);
      }
        // write old items
      for (uint64_t s = nr_merged_segment; s--;) {
        // update old page buffer
        uint32_t cur_segment = merged_segment[s];

        // get old box
        const uint16_t * const pboxid_old = (typeof(pboxid_old))ptr_old[s];
        const uint64_t boxid_old = (uint64_t)(*pboxid_old);
        assert(boxid_old == i);

        const uint16_t * const pboxlen_old = (typeof(pboxlen_old))(ptr_old[s] + sizeof(*pboxid_old));
        const uint64_t boxlen_old = (uint64_t)(*pboxlen_old);
        const uint8_t * pbox_old = ptr_old[s] + sizeof(*pboxid_old) + sizeof(*pboxlen_old);

        uint64_t alllen_old = sizeof(*pboxid_old) + sizeof(*pboxlen_old) + boxlen_old;

// fprintf(stderr, "(s%lu,len%lu)", cur_segment, boxlen_old);
        if (alllen_old <= BARREL_ALIGN){
          memcpy(pbox_new, pbox_old, boxlen_old);
          pbox_new += boxlen_old;
        }
        else {
          while (alllen_old > BARREL_ALIGN) {
            uint64_t copy_size = BARREL_ALIGN - (pbox_old - ptr_old[s]);
            memcpy(pbox_new, pbox_old, copy_size);
            pbox_new += copy_size;
            alllen_old -= BARREL_ALIGN;

            old_page[s]++;

            ssize_t offset = old_page[s] * BARREL_ALIGN;
            const ssize_t nbi = pread(bc->raw_fd, old + BARREL_ALIGN * s, BARREL_ALIGN, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
            assert(nbi == ((ssize_t)BARREL_ALIGN));
            ptr_old[s] = old + BARREL_ALIGN * s;
            pbox_old = ptr_old[s];
          }
          memcpy(pbox_new, pbox_old, alllen_old);
          pbox_new += alllen_old;

        }

        ptr_old[s] += alllen_old;
      }

      if (alllen_new > BARREL_ALIGN) {
        while (alllen_new > 0) {
          alllen_new -= BARREL_ALIGN;
          page += BARREL_ALIGN;
          if (alllen_new < BARREL_ALIGN)
            bzero(page + alllen_new, BARREL_ALIGN - alllen_new);

          index_last[current_page] = i + p * TABLE_MAX_BARRELS;
          current_page++;
        }
      }
      else
        off_page += alllen_new;

    }
    if (off_page != 0) {
      bzero(page + off_page, BARREL_ALIGN - off_page);
      page += BARREL_ALIGN;
      off_page = 0;
      index_last[current_page] = TABLE_MAX_BARRELS - 1 + p * TABLE_MAX_BARRELS;
      current_page++;
    }
  }
// fprintf(stderr, "current_page %lu\n", current_page);

  // bloomcontainer_check(pages, current_page, bc->nr_bf_per_box[bc->cur_segment] + bt_count, index_last);

// fprintf(stderr, "pages_cap :%lu, current_page %lu\n", pages_cap, current_page * BARREL_ALIGN);

  uint32_t container_unit_count = 0;
  uint64_t off_raws[NR_PAGES_BF_MAX];
  int64_t nr_raw_bytes = (typeof(nr_raw_bytes))(current_page * BARREL_ALIGN);

  page = pages;
  while (nr_raw_bytes > 0) {
    const uint64_t off_raw = containermap_alloc(cm);
    assert(off_raw < cm->total_cap);
    const ssize_t write_size = TABLE_ALIGN > nr_raw_bytes ? nr_raw_bytes : TABLE_ALIGN;
    // write container
    const ssize_t nrb = pwrite(cm->raw_fd, page, write_size, off_raw);
    assert(nrb == write_size);
    
    off_raws[container_unit_count] = off_raw;
    page += write_size;
    nr_raw_bytes -= write_size;
    container_unit_count += 1;
  }

  huge_free(pages, pages_cap);
  // slab_free(slab, pages);
  stat_inc_n(&(stat->nr_write_bc), current_page);

  uint32_t nr_bf_per_box = bt_count;
  for (uint64_t s = nr_merged_segment; s--;) {
    uint32_t cur_segment = merged_segment[s];
    // fprintf(stderr, "merged_segment %u, nr_bf_per_box %u\n", cur_segment, bc->nr_bf_per_box[cur_segment]);
    nr_bf_per_box += bc->nr_bf_per_box[cur_segment];
  }
  // fprintf(stderr, "nr_bf_per_box %d\n", nr_bf_per_box);

  struct SegmentBloomContainer *bc_new;
  // alloc new bc
  const uint64_t size_bc = sizeof(struct SegmentBloomContainer);
  bc_new = (typeof(bc_new))malloc(size_bc);
  assert(bc_new);
  bzero(bc_new, size_bc);

  for (uint64_t i = 0; i < cur_segment_new; i++) {
    bc_new->container_unit_count[i] = bc->container_unit_count[i];
    memcpy(bc_new->off_raw[i], bc->off_raw[i], sizeof(bc_new->off_raw[i][0]) * NR_PAGES_BF_MAX);
    bc_new->max_box_len[i] = bc->max_box_len[i];
    bc_new->nr_bf_per_box[i] = bc->nr_bf_per_box[i];
    bc_new->nr_index[i] = bc->nr_index[i];
    bc_new->index_last[i] = (typeof(bc_new->index_last[i]))malloc(sizeof(index_last[0]) * bc_new->nr_index[i]);
    memcpy(bc_new->index_last[i], bc->index_last[i], sizeof(index_last[0]) * bc_new->nr_index[i]);
  }

  bc_new->raw_fd = cm->raw_fd;
  bc_new->nr_bf = bc->nr_bf + bt_count;
  bc_new->nr_barrels = bc->nr_barrels;
  bc_new->cur_segment = cur_segment_new;

  bc_new->container_unit_count[bc_new->cur_segment] = container_unit_count;
  for (uint64_t i = 0; i < container_unit_count; i++)
    bc_new->off_raw[bc_new->cur_segment][i] = off_raws[i];

  bc_new->max_box_len[bc_new->cur_segment] = max_box_len;
  bc_new->nr_bf_per_box[bc_new->cur_segment] = nr_bf_per_box; // ++
  bc_new->nr_index[bc_new->cur_segment] = current_page;
  bc_new->index_last[bc_new->cur_segment] = (typeof(bc_new->index_last[bc_new->cur_segment]))malloc(sizeof(index_last[0]) * current_page);
  memcpy(bc_new->index_last[bc_new->cur_segment], index_last, sizeof(index_last[0]) * current_page);

  bc_new->cur_segment = cur_segment_post;

  return bc_new;
}

  bool
bloomcontainer_fetch_raw(struct BloomContainer * const bc, const uint64_t barrel_id, uint8_t * const buf)
{
  for (uint64_t i = 0; i < bc->nr_index; i++) {
    if (bc->index_last[i] >= barrel_id) {
      // fetch page at [i]
      ssize_t offset = BARREL_ALIGN * i;
      const ssize_t nr = pread(bc->raw_fd, buf, BARREL_ALIGN, bc->off_raw[offset / TABLE_ALIGN] + (offset % TABLE_ALIGN));
      assert(nr == ((ssize_t)BARREL_ALIGN));

      const uint16_t *plen = (typeof(plen))(buf + sizeof(uint16_t));
      const ssize_t bfs_size = *plen + sizeof(*plen) + sizeof(uint16_t);

      if (bfs_size > BARREL_ALIGN) {
        offset += BARREL_ALIGN;
        ssize_t extra_size = ((bfs_size - 1) / BARREL_ALIGN) * BARREL_ALIGN;
        assert(extra_size < 8 * BARREL_ALIGN);
        if (offset / TABLE_ALIGN == (offset + extra_size - 1) / TABLE_ALIGN) {
          const ssize_t nr2 = pread(bc->raw_fd, buf + BARREL_ALIGN, extra_size, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr2 == extra_size);
        }
        else {
          ssize_t part_size = TABLE_ALIGN - (offset % TABLE_ALIGN);
          const ssize_t nr2 = pread(bc->raw_fd, buf + BARREL_ALIGN, part_size, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr2 == part_size);
          offset += part_size;

          extra_size -= part_size;
          const ssize_t nr3 = pread(bc->raw_fd, buf + BARREL_ALIGN + part_size, extra_size, bc->off_raw[offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr3 == extra_size);
        }
      }

      return true;
    }
  }
  return false;
}

int bloom_test_pause() {
  int a = 1;
  return a + 1;
}

  bool
segmentbloomcontainer_fetch_raw(struct SegmentBloomContainer * const bc, uint32_t cur_segment, const uint64_t barrel_id, uint64_t h, uint8_t * const buf)
{
  uint32_t partition = SuperFastHash(h) % NR_PARTITIONS;
  for (uint64_t i = 0; i < bc->nr_index[cur_segment]; i++) {
    if (bc->index_last[cur_segment][i] >= TABLE_MAX_BARRELS * NR_PARTITIONS) {
      fprintf(stderr, "error index_last, i %lu, barrel_id %lu\n", i, barrel_id);
      bloom_test_pause();
    }
    if (bc->index_last[cur_segment][i] >= barrel_id + partition * TABLE_MAX_BARRELS) {
      // fetch page at [i]
      // todo
      // 
      ssize_t offset = BARREL_ALIGN * i;
      const ssize_t nr = pread(bc->raw_fd, buf, BARREL_ALIGN, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
      assert(nr == ((ssize_t)BARREL_ALIGN));

      const uint16_t *plen = (typeof(plen))(buf + sizeof(uint16_t));
      const ssize_t bfs_size = *plen + sizeof(*plen) + sizeof(uint16_t);
      if (bfs_size > BARREL_ALIGN) {
        offset += BARREL_ALIGN;
        ssize_t extra_size = ((bfs_size - 1) / BARREL_ALIGN) * BARREL_ALIGN;
        assert(extra_size < 8 * BARREL_ALIGN);
        if (offset / TABLE_ALIGN == (offset + extra_size - 1) / TABLE_ALIGN) {
          const ssize_t nr2 = pread(bc->raw_fd, buf + BARREL_ALIGN, extra_size, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr2 == extra_size);
        }
        else {
          ssize_t part_size = TABLE_ALIGN - (offset % TABLE_ALIGN);
          const ssize_t nr2 = pread(bc->raw_fd, buf + BARREL_ALIGN, part_size, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr2 == part_size);
          offset += part_size;

          extra_size -= part_size;
          const ssize_t nr3 = pread(bc->raw_fd, buf + BARREL_ALIGN + part_size, extra_size, bc->off_raw[cur_segment][offset / TABLE_ALIGN] + offset % TABLE_ALIGN);
          assert(nr3 == extra_size);
        }
      }
      return true;
    }
  }
  return false;
}

  bool
bloomcontainer_dump_meta(struct BloomContainer * const bc, FILE * const fo)
{
  assert(bc);
  assert(fo);
  const size_t ncuc = fwrite(&(bc->container_unit_count), sizeof(bc->container_unit_count), 1, fo);
  assert(ncuc == 1);
  const size_t noff = fwrite((bc->off_raw), sizeof(bc->off_raw[0]), NR_PAGES_BF_MAX, fo);
  assert(noff == NR_PAGES_BF_MAX);
  const size_t nbar = fwrite(&(bc->nr_barrels), sizeof(bc->nr_barrels), 1, fo);
  assert(nbar == 1);
  const size_t nbpb = fwrite(&(bc->nr_bf_per_box), sizeof(bc->nr_bf_per_box), 1, fo);
  assert(nbpb == 1);
  const size_t nnri = fwrite(&(bc->nr_index), sizeof(bc->nr_index), 1, fo);
  assert(nnri == 1);
  const size_t nidx = fwrite(bc->index_last, sizeof(bc->index_last[0]), bc->nr_index, fo);
  assert(nidx == bc->nr_index);
  return true;
}

  struct BloomContainer *
bloomcontainer_load_meta(FILE * const fi, const int raw_fd)
{
  struct BloomContainer bc0;
  assert(fi);
  struct BloomContainer * const bc = (typeof(bc))malloc(sizeof(*bc) + (sizeof(bc->index_last[0]) * bc0.nr_index));
  assert(bc);
  const size_t ncuc = fread(&(bc0.container_unit_count), sizeof(bc0.container_unit_count), 1, fi);
  assert(ncuc == 1);
  const size_t noff = fread((bc->off_raw), sizeof(bc->off_raw[0]), NR_PAGES_BF_MAX, fi);
  assert(noff == NR_PAGES_BF_MAX);
  const size_t nbar = fread(&(bc0.nr_barrels), sizeof(bc0.nr_barrels), 1, fi);
  assert(nbar == 1);
  const size_t nbpb = fread(&(bc0.nr_bf_per_box), sizeof(bc0.nr_bf_per_box), 1, fi);
  assert(nbpb == 1);
  const size_t nnri = fread(&(bc0.nr_index), sizeof(bc0.nr_index), 1, fi);
  assert(nnri == 1);
  bc->raw_fd = raw_fd;
  bc->container_unit_count = bc0.container_unit_count;
  bc->nr_barrels = bc0.nr_barrels;
  bc->nr_bf_per_box = bc0.nr_bf_per_box;
  bc->nr_index = bc0.nr_index;
  const size_t nidx = fread(bc->index_last, sizeof(bc->index_last[0]), bc->nr_index, fi);
  assert(nidx == bc->nr_index);
  return bc;
}

  static uint64_t
bloomcontainer_match_nr(struct BloomContainer * const bc, const uint8_t *const pbox, const uint64_t hv, uint8_t *ret)
{
  const uint8_t *ptr = pbox;
  const uint64_t nr_bf = bc->nr_bf_per_box;
  uint64_t bits = 0;
  for (uint64_t i = 0; i < nr_bf; i++) {
    uint32_t blen;
    const uint8_t * const pbf = decode_uint32(ptr, &blen);
    assert(pbf > ptr);
    assert(blen);
    const bool match = bloom_match_raw(pbf, blen, hv);
    if (match) {
      const uint64_t l = (nr_bf - i - 1); // nr_bf = x+1; 0-x => x-0
      ret[l >> 3] |= (UINT64_C(1) << (l % 8));
    }
    ptr = pbf + blen;
  }
  return bits;
}

  bool
segmentbloomcontainer_dump_meta(struct SegmentBloomContainer * const bc, FILE * const fo)
{
  assert(bc);
  assert(fo);
  const size_t nbf = fwrite(&(bc->nr_bf), sizeof(bc->nr_bf), 1, fo);
  assert(nbf == 1);
  const size_t ncs = fwrite(&(bc->cur_segment), sizeof(bc->cur_segment), 1, fo);
  assert(ncs == 1);
  const size_t nbar = fwrite(&(bc->nr_barrels), sizeof(bc->nr_barrels), 1, fo);
  assert(nbar == 1);
  const size_t ncuc = fwrite(bc->container_unit_count, sizeof(bc->container_unit_count[0]), NR_SEGMENTS_MAX, fo);
  assert(ncuc == NR_SEGMENTS_MAX);

  for (int i = 0; i < NR_SEGMENTS_MAX; i++) {
    const size_t noff = fwrite(bc->off_raw[i], sizeof(bc->off_raw[0][0]), NR_PAGES_BF_MAX, fo);
    assert(noff == NR_PAGES_BF_MAX);
  }
  
  const size_t nbpb = fwrite(bc->nr_bf_per_box, sizeof(bc->nr_bf_per_box[0]), NR_SEGMENTS_MAX, fo);
  assert(nbpb == NR_SEGMENTS_MAX);
  const size_t nnri = fwrite(bc->nr_index, sizeof(bc->nr_index[0]), NR_SEGMENTS_MAX, fo);
  assert(nnri == NR_SEGMENTS_MAX);
  for (int i = 0; i < NR_SEGMENTS_MAX; i++) {
    if (bc->nr_index[i] != 0) {
      const size_t nidx = fwrite(bc->index_last[i], sizeof(bc->index_last[i][0]), bc->nr_index[i], fo);
      assert(nidx == bc->nr_index[i]);
    }
  }
  return true;
}

  struct SegmentBloomContainer *
segmentbloomcontainer_load_meta(FILE * const fo, const int raw_fd)
{
  assert(fo);
  struct SegmentBloomContainer * const bc = (typeof(bc))malloc(sizeof(*bc));
  assert(bc);
  bzero(bc, sizeof(*bc));

  bc->raw_fd = raw_fd;
  const size_t nbf = fread(&(bc->nr_bf), sizeof(bc->nr_bf), 1, fo);
  assert(nbf == 1);
  const size_t ncs = fread(&(bc->cur_segment), sizeof(bc->cur_segment), 1, fo);
  assert(ncs == 1);
  const size_t nbar = fread(&(bc->nr_barrels), sizeof(bc->nr_barrels), 1, fo);
  assert(nbar == 1);
  const size_t ncuc = fread(bc->container_unit_count, sizeof(bc->container_unit_count[0]), NR_SEGMENTS_MAX, fo);
  assert(ncuc == NR_SEGMENTS_MAX);
  for (int i = 0; i < NR_SEGMENTS_MAX; i++) {
    const size_t noff = fread(bc->off_raw[i], sizeof(bc->off_raw[0][0]), NR_PAGES_BF_MAX, fo);
    assert(noff == NR_PAGES_BF_MAX);
  }
  const size_t nbpb = fread(bc->nr_bf_per_box, sizeof(bc->nr_bf_per_box[0]), NR_SEGMENTS_MAX, fo);
  assert(nbpb == NR_SEGMENTS_MAX);
  const size_t nnri = fread(bc->nr_index, sizeof(bc->nr_index[0]), NR_SEGMENTS_MAX, fo);
  assert(nnri == NR_SEGMENTS_MAX);
  for (int i = 0; i < NR_SEGMENTS_MAX; i++) {
    if (bc->nr_index[i] != 0) {
      bc->index_last[i] = (typeof(bc->index_last[i]))malloc(sizeof(bc->index_last[i][0]) * bc->nr_index[i]);
      const size_t nidx = fread(bc->index_last[i], sizeof(bc->index_last[i][0]), bc->nr_index[i], fo);
      assert(nidx == bc->nr_index[i]);
    }
  }

  return bc;
}

// return bitmap. 0: no match
  uint64_t
bloomcontainer_match(struct BloomContainer * const bc, const uint32_t index, const uint64_t hv, uint8_t *ret)
{
  uint8_t boxpage[BARREL_ALIGN * 8] __attribute__((aligned(4096)));
  const bool rf = bloomcontainer_fetch_raw(bc, (uint64_t)index, boxpage);
  assert(rf);

  const uint16_t *boxlen = (typeof(boxlen))(boxpage + sizeof(uint16_t));
  ssize_t read_size = *boxlen + sizeof(*boxlen) + sizeof(uint16_t);
  read_size = ((read_size + BARREL_ALIGN - 1) / BARREL_ALIGN);

  uint8_t *ptr = boxpage;
  for (;;) {
    const uint16_t *pid = (typeof(pid))ptr;
    const uint16_t id = *pid;
    const uint16_t *plen = (typeof(plen))(ptr + sizeof(*pid));
    if (id == index) {
      // match one by one
      uint8_t *pbox = (typeof(pbox))(ptr + sizeof(*pid) + sizeof(*plen));
      bloomcontainer_match_nr(bc, pbox, hv, ret);
      return read_size;
    } else if (id < index) { // next
      ptr += (sizeof(*pid) + sizeof(*plen) + *plen);
    } else { // id > index
      return 0;
    }
  }
}

  void
bloomcontainer_free(struct BloomContainer *const bc)
{
  free(bc->index_last);
  free(bc);
}


  static bool
segmentbloomcontainer_match_nr(struct SegmentBloomContainer * const bc, uint32_t cur_segment, const uint8_t *const pbox, const uint64_t hv, uint8_t *ret, uint64_t len)
{
  const uint8_t *ptr = pbox;
  const uint64_t nr_bf = bc->nr_bf_per_box[cur_segment];
  uint32_t pre_nr_bf = 0;
  for (uint64_t i = 0; i < cur_segment; i++)
    pre_nr_bf += bc->nr_bf_per_box[i];

  // uint64_t bits = 0;
bool hit = false;
  for (uint64_t i = 0; i < nr_bf; i++) {
    uint64_t blen;
    const uint8_t * const pbf = decode_uint64(ptr, &blen);
    assert(pbf > ptr);
    // assert(blen);
    if (blen == 0) {
      fprintf(stderr, "in segmentbloomcontainer_match_nr, blen = 0 !!!\n");fflush(stderr);
      while (true) {
        sleep(10);
      }
    }

    const bool match = bloom_match_raw(pbf, blen, hv);
    // bool match = true;
    if (match) {
  hit = true;
      const uint64_t l = (nr_bf - i - 1) + pre_nr_bf; // nr_bf = x+1; 0-x => x-0

      ret[l >> 3] |= (UINT64_C(1) << (l % 8));
    }
    ptr = pbf + blen;

    if (ptr - pbox > len) {
      fprintf(stderr, "error bf box, actual bfs %lu\n", i - 1);
    }
  }
// static bool debug = false;
// if (!hit || debug) {
//   debug = true;
//   ptr = pbox;
//   fprintf(stderr, "debug:\n");
//   for (uint64_t i = 0; i < nr_bf; i++) {
//     uint64_t blen;
//     const uint8_t * const pbf = decode_uint64(ptr, &blen);
//     assert(pbf > ptr);
//     assert(blen);
//     fprintf(stderr, "(b%lu,len%lu)\n", (nr_bf - i - 1), blen);
//     for(int j = 0; j < blen; j++){
//       uint8_t c = *(pbf+j);
//       fprintf(stderr, "%d,", (int)c);
//     }
//     fprintf(stderr, "\n");
//     ptr = pbf + blen;
//   }
//   fprintf(stderr, "\n\n");
//   // bloom_test_pause();
// }
return hit;
  // return bits;
}

uint32_t segmentbloomcontainer_match_per_segment(struct SegmentBloomContainer * const bc, uint32_t cur_segment, const uint32_t index, const uint64_t hv, uint8_t *ret)
{
  uint8_t boxpage[BARREL_ALIGN * 8] __attribute__((aligned(4096)));

  const bool rf = segmentbloomcontainer_fetch_raw(bc, cur_segment, (uint64_t)index, hv, boxpage);
  assert(rf);

  const uint16_t *boxlen = (typeof(boxlen))(boxpage + sizeof(uint16_t));
  ssize_t read_size = *boxlen + sizeof(*boxlen) + sizeof(uint16_t);
  read_size = ((read_size + BARREL_ALIGN - 1) / BARREL_ALIGN);

  uint8_t *ptr = boxpage;
  for (;;) {
    const uint16_t *pid = (typeof(pid))ptr;
    const uint16_t id = *pid;
    const uint16_t *plen = (typeof(plen))(ptr + sizeof(*pid));
    if (id == index) {
      // match one by one
      uint8_t *pbox = (typeof(pbox))(ptr + sizeof(*pid) + sizeof(*plen));

      bool hit =  segmentbloomcontainer_match_nr(bc, cur_segment, pbox, hv, ret, (uint64_t) *plen);
      if (!hit) {
          // bloom_test_pause();
        // exit(1);
      }

      return read_size;
    } else if (id < index) { // next
      ptr += (sizeof(*pid) + sizeof(*plen) + *plen);
    } else { // id > index
      assert(false);
      return 0;
    }
  }
}

// return bitmap. 0: no match
  uint32_t
segmentbloomcontainer_match(struct SegmentBloomContainer * const bc, const uint32_t index, const uint64_t hv, uint8_t *ret)
{
  uint32_t read_size = 0;
  for (uint64_t i = 0; i <= bc->cur_segment; i++)
    if (bc->container_unit_count[i] != 0)
      read_size += segmentbloomcontainer_match_per_segment(bc, i, index, hv, ret);
  return read_size;
}

  void
segmentbloomcontainer_free(struct SegmentBloomContainer *const bc)
{
  for (uint64_t i = 0; i <= bc->cur_segment; i++)
    free(bc->index_last[i]);
  free(bc);
}