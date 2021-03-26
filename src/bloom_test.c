/*
 * Copyright (c) 2014  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include "generator.h"
#include "debug.h"
#include "mempool.h"
#include "bloom.h"
#include "cmap.h"
#include "table.h"


  void
uncached_probe_test(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srandom(tv.tv_usec);
  const uint64_t nr_units = 1024*256;
  const uint64_t usize = 4096;
  uint8_t * const bf0 = malloc(usize * nr_units);
  struct BloomFilter * bfs[nr_units];

  for (uint64_t i = 0; i < nr_units; i++) {
    struct BloomFilter * const bf = (typeof(bf))(bf0 + (i * usize));
    memset(bf, -1, usize);
    bf->bytes = 4000;
    bfs[i] = bf;
  }
  const uint64_t times = UINT64_C(80000000);
  struct timeval t0, t1;
  gettimeofday(&t0, NULL);
  for (uint64_t i = 0; i < times; i++) {
    const uint64_t r = random_uint64();
    const uint64_t k = random_uint64();
    const bool b = bloom_match(bfs[r % nr_units], k);
    assert(b == true);
  }
  gettimeofday(&t1, NULL);
  free(bf0);
  const uint64_t dt = debug_tv_diff(&t0, &t1);
  printf("probe %" PRIu64 " times over 1GB, %" PRIu64" usec, %.2lf p/s\n",
      times, dt, ((double)times) * 1000000.0 / ((double)dt));
}

  void
false_positive_test(void)
{
  // random seed
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srandom(tv.tv_usec);
  uint64_t probes = 0;
  uint64_t fps = 0;

  for (int i = 0; i < 10; i++) {
    struct Mempool * const p = mempool_new(4096*4096);
    const uint64_t nr_keys = 64;
    const uint64_t nr_probes = nr_keys * 65536;
    uint64_t * const keys = (typeof(keys))malloc(sizeof(keys[0]) * nr_keys);

    struct BloomFilter *bf = bloom_create(nr_keys, p);
    // put nr_keys keys
    for (uint64_t j = 0; j < nr_keys; j++) {
      const uint64_t h = random_uint64();
      bloom_update(bf, h);
      keys[j] = h;
    }
    // true-positive
    for (uint64_t j = 0; j < nr_keys; j++) {
      assert(bloom_match(bf, keys[j]));
    }

    uint64_t fp = 0;
    uint64_t j = 0;
    while(j < nr_probes) {
      const uint64_t h = random_uint64();
      bool nonex = true;
      for (uint64_t k = 0; k < nr_keys; k++) {
        if(h == keys[k]) {
          nonex = false;
          break;
        }
      }

      if (nonex) {
        if (bloom_match(bf, h)) {
          fp++;
        }
        j++;
      }
    }
    const double fprate = ((double)fp) / ((double)nr_probes);
    printf("%" PRIu64 " out of %" PRIu64 ": %lf, ", fp, nr_probes, fprate);
    printf(" 8 %5.2lf  ", fprate *  8.0 * 100.0);
    printf("32 %5.2lf  ", fprate * 32.0 * 100.0);
    printf("40 %5.2lf  ", fprate * 40.0 * 100.0);
    printf("48 %5.2lf  ", fprate * 48.0 * 100.0);
    printf("56 %5.2lf  ", fprate * 56.0 * 100.0);
    printf("64 %5.2lf\n", fprate * 64.0 * 100.0);
    mempool_free(p);
    fps += fp;
    probes += nr_probes;
  }
  const double fprateall = ((double)fps) / ((double)probes);
  printf("%" PRIu64 " out of %" PRIu64 ": %lf, ", fps, probes, fprateall);
  printf(" 8: %5.2lf  ", fprateall *  8.0 * 100.0);
  printf("32: %5.2lf  ", fprateall * 32.0 * 100.0);
  printf("40: %5.2lf  ", fprateall * 40.0 * 100.0);
  printf("48: %5.2lf  ", fprateall * 48.0 * 100.0);
  printf("56: %5.2lf  ", fprateall * 56.0 * 100.0);
  printf("64: %5.2lf\n", fprateall * 64.0 * 100.0);
}

  void
pbf_false_positive_test(void)
{
  // random seed
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srandom(tv.tv_usec);
  uint64_t probes = 0;
  uint64_t fps = 0;
  printf("Test pbf false positive\n");
  for (int i = 0; i < 10; i++) {
    struct Mempool * const p = mempool_new(4096*4096);
    const uint64_t nr_keys = 64;
    const uint64_t nr_probes = nr_keys * 65536;
    uint64_t * const keys = (typeof(keys))malloc(sizeof(keys[0]) * nr_keys);

    // put nr_keys keys
    for (uint64_t j = 0; j < nr_keys; j++) {
      const uint64_t h = random_uint64();
      keys[j] = h;
    }
    struct BloomFilterGroup *bf = bloom_create_update(nr_keys, keys, p);
    // true-positive
    for (uint64_t j = 0; j < nr_keys; j++) {
      assert(bloom_group_match(bf, keys[j]));
    }

    uint64_t fp = 0;
    uint64_t j = 0;
    while(j < nr_probes) {
      const uint64_t h = random_uint64();
      bool nonex = true;
      for (uint64_t k = 0; k < nr_keys; k++) {
        if(h == keys[k]) {
          nonex = false;
          break;
        }
      }

      if (nonex) {
        if (bloom_group_match(bf, h)) {
          fp++;
        }
        j++;
      }
    }
    const double fprate = ((double)fp) / ((double)nr_probes);
    printf("%" PRIu64 " out of %" PRIu64 ": %lf, ", fp, nr_probes, fprate);
    printf(" 8 %5.2lf  ", fprate *  8.0 * 100.0);
    printf("32 %5.2lf  ", fprate * 32.0 * 100.0);
    printf("40 %5.2lf  ", fprate * 40.0 * 100.0);
    printf("48 %5.2lf  ", fprate * 48.0 * 100.0);
    printf("56 %5.2lf  ", fprate * 56.0 * 100.0);
    printf("64 %5.2lf\n", fprate * 64.0 * 100.0);
    mempool_free(p);
    fps += fp;
    probes += nr_probes;
  }
  const double fprateall = ((double)fps) / ((double)probes);
  printf("%" PRIu64 " out of %" PRIu64 ": %lf, ", fps, probes, fprateall);
  printf(" 8: %5.2lf  ", fprateall *  8.0 * 100.0);
  printf("32: %5.2lf  ", fprateall * 32.0 * 100.0);
  printf("40: %5.2lf  ", fprateall * 40.0 * 100.0);
  printf("48: %5.2lf  ", fprateall * 48.0 * 100.0);
  printf("56: %5.2lf  ", fprateall * 56.0 * 100.0);
  printf("64: %5.2lf\n", fprateall * 64.0 * 100.0);
}

  void
multi_level_false_positive_test(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  srandom(tv.tv_usec);

  struct Mempool *p = mempool_new(256*1024*1024);
  const uint64_t nr_keys = 64;
  const uint64_t nr_inserted_keys = 64;

  const uint64_t nr_levels = 200;
  const uint64_t nr_all_keys = nr_keys * nr_levels;

  uint64_t * const keys = (typeof(keys))malloc(sizeof(keys[0]) * nr_all_keys);
  struct BloomFilter *bfs[nr_levels] = {NULL};

  for (uint64_t l = 0; l < nr_levels; l++) {
    bfs[l] = bloom_create(nr_keys, p);
    // put nr_keys keys and remember in keys[]
    for (uint64_t k = 0; k < nr_inserted_keys; k++) {
      const uint64_t h = random_uint64();
      bloom_update(bfs[l], h);
      keys[l * nr_keys + k] = h;
    }
    // true-positive
    for (uint64_t k = 0; k < nr_inserted_keys; k++) {
      assert(bloom_match(bfs[l], keys[l * nr_keys + k]));
    }
  }

  // check keys in the last level
  uint64_t fp = 0;
  const uint64_t level = nr_levels - 1;
  for (uint64_t l = 0; l < level; l++) {
    for (uint64_t k = 0; k < nr_inserted_keys; k++) {
      const bool m = bloom_match(bfs[l], keys[level * nr_keys + k]);
      if (m) fp++;
    }
  }
  printf("multi-level exist keys fp: %" PRIu64 " levels, %" PRIu64 " keys/level, %" PRIu64 " probes, %" PRIu64 " f-p, %.3lf%%\n",
      nr_levels, nr_keys, level * nr_keys, fp, ((double)fp) * 100.0 /((double)nr_keys));
  fp = 0;
  const uint64_t nr_nonprobe = 10000;
  for (uint64_t l = 0; l < level; l++) {
    for (uint64_t k = 0; k < nr_nonprobe; k++) {
      const uint64_t h = random_uint64();
      const bool m = bloom_match(bfs[l], h);
      if (m) fp++;
    }
  }
  printf("multi-level non-exist keys fp: %" PRIu64 " levels, %" PRIu64 " probes, %" PRIu64 " f-p, %.3lf%%\n",
      nr_levels, level * nr_nonprobe, fp, ((double)fp) * 100.0 /((double)nr_nonprobe));

  mempool_free(p);
}

bool testfound(uint8_t *bitmap, uint32_t count) {
  for (uint32_t i = 0; i < count; i += 1) {
    // ptr = (typeof(ptr))(bitmap + i);
    // if (*ptr != 0) {
    //   return true;
    // }
    if (bitmap[i] != 0) {
      return true;
    }
  }
  return false;
}

// test bloom-container
  void
containertest(void)
{
  const uint64_t xcap = 32;
  const uint64_t max_level = 8;
  struct Mempool *mp = mempool_new(xcap * 4096 * 8);
  struct BloomFilter *bfs[8][xcap];
  struct BloomTable *bts[8];
  struct BloomContainer *bcs[8];
  uint8_t hash[20];
  struct Stat stat;
  bzero(&stat, sizeof(stat));

  const char * const raw_fn = "/tmp/raw_test";
  const uint64_t cap = UINT64_C(1024 * 1024) * 32 * 64;

  // create
  struct ContainerMap * const cm = containermap_create(raw_fn, cap);
  assert(cm);

  // bf & bt
  for (uint64_t z = 0; z < 8; z++) { // level
    for (uint64_t i = 0; i < xcap; i++) { // index
      bfs[z][i] = bloom_create(64, mp);
      for (uint64_t j = 0; j < 64; j++) { // key id
        const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
        SHA1((const unsigned char *)(&h), 8, hash);
        const uint64_t sha = *((uint64_t *)(&hash[7]));
        bloom_update(bfs[z][i], sha);
      }
    }
    bts[z] = bloomtable_build(bfs[z], xcap);
    assert(bts[z]);
  }

  // bc
  const int rawfd = open("/tmp/bctest", O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 00666);
  assert(rawfd >= 0);
  bcs[0] = bloomcontainer_build(bts[0], rawfd, 0, &stat);
  assert(bcs[0]);
  uint64_t match=0;
  uint64_t nomatch =0;
  for (uint64_t i = 0; i < xcap; i++) {
    for (uint64_t j = 0; j < 64; j++) {
      uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
      uint8_t bitmap2[max_level] __attribute__ ((aligned(8))) = {0};

      const uint64_t h = i + (j << 20) + (j << 30) + (j << 40);
      SHA1((const unsigned char *)(&h), 8, hash);
      const uint64_t sha = *((uint64_t *)(&hash[7]));
      const uint8_t m = bloomcontainer_match(bcs[0], i, sha, bitmap);
      assert(testfound(bitmap, max_level));
      const uint8_t n = bloomcontainer_match(bcs[0], i, sha+1, bitmap2);
      if (testfound(bitmap2, max_level)) match ++; else nomatch++;
    }
  }
  printf("match %" PRIu64 ", nomatch %" PRIu64 " (m/n should < 1%%)\n", match, nomatch);
  printf("build[0] ok\n");

  bcs[1] = bloomcontainer_update(cm, bcs[0], bts[1], &stat);
  printf("update[1] ok\n");
  uint64_t match01[4]={0};
  for (uint64_t i = 0; i < xcap; i++) {
    for (uint64_t j = 0; j < 64; j++) {
      uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
      uint8_t bitmap2[max_level] __attribute__ ((aligned(8))) = {0};

      const uint64_t h0 = i + (j << 20) + (j << 30) + (j << 40);
      SHA1((const unsigned char *)(&h0), 8, hash);
      const uint64_t sha0 = *((uint64_t *)(&hash[7]));
      const uint8_t m0 = bloomcontainer_match(bcs[1], i, sha0, bitmap);
      assert(testfound(bitmap, max_level));
      const uint64_t h1 = i + (j << 20) + (j << 30) + (j << 40) + (UINT64_C(1) << 50);
      SHA1((const unsigned char *)(&h1), 8, hash);
      const uint64_t sha1 = *((uint64_t *)(&hash[7]));
      const uint8_t m1 = bloomcontainer_match(bcs[1], i, sha1, bitmap2);
      assert(testfound(bitmap2, max_level));
    }
  }
  printf("match1:%" PRIu64 ", 2:%" PRIu64 "\n", match01[1], match01[2]);

  bcs[2] = bloomcontainer_update(cm, bcs[1], bts[2], &stat);
  printf("update[2] ok\n");
  bcs[3] = bloomcontainer_update(cm, bcs[2], bts[3], &stat);
  printf("update[3] ok\n");
  bcs[4] = bloomcontainer_update(cm, bcs[3], bts[4], &stat);
  printf("update[4] ok\n");
  bcs[5] = bloomcontainer_update(cm, bcs[4], bts[5], &stat);
  printf("update[5] ok\n");
  bcs[6] = bloomcontainer_update(cm, bcs[5], bts[6], &stat);
  printf("update[6] ok\n");
  bcs[7] = bloomcontainer_update(cm, bcs[6], bts[7], &stat);
  printf("update[7] ok\n");

  // match
  match = 0;
  nomatch = 0;
  uint64_t mc[8] = {0};
  uint64_t mismatch = 0;
  for (uint64_t z = 0; z < 8; z++) {
    for (uint64_t i = 0; i < xcap; i++) {
      for (uint64_t j = 0; j < 64; j++) {
        uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
        uint8_t bitmap2[max_level] __attribute__ ((aligned(8))) = {0};

        const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
        SHA1((const unsigned char *)(&h), 8, hash);
        const uint64_t sha = *((uint64_t *)(&hash[7]));
        const uint8_t m = bloomcontainer_match(bcs[7], i, sha, bitmap);
        assert(testfound(bitmap, max_level));
        mc[z]++;
        const uint8_t n = bloomcontainer_match(bcs[7], i, sha+1, bitmap2);
        if (testfound(bitmap2, max_level)) match ++; else nomatch++;
      }
    }
  }
  printf("match count[0-7]:%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " mismatch %" PRIu64 "\n",
      mc[0], mc[1], mc[2], mc[3], mc[4], mc[5], mc[6], mc[7], mismatch);
  printf("containertest: passed\n");
}

// test bloom-container
  void
containerperf(void)
{
  const uint64_t xcap = TABLE_MAX_BARRELS; // # of barrels
  const uint64_t max_level = 200;
  const uint64_t nr_keys = 64;
  struct Mempool *mp = mempool_new(xcap * 4096 * max_level);
  struct BloomFilter *bfs[max_level][xcap];
  struct BloomTable *bts[max_level];
  struct BloomContainer *bcs;
  uint8_t hash[20];
  struct Stat stat;
  bzero(&stat, sizeof(stat));

  const char * const raw_fn = "/tmp/raw_test";
  uint64_t cap = UINT64_C(1024 * 1024) * max_level * 64;

  // create
  struct ContainerMap * const cm = containermap_create(raw_fn, cap);
  assert(cm);

  // bf & bt
  for (uint64_t z = 0; z < max_level; z++) { // level
    for (uint64_t i = 0; i < xcap; i++) { // index
      bfs[z][i] = bloom_create(nr_keys, mp);
      for (uint64_t j = 0; j < nr_keys; j++) { // key id
        const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
        SHA1((const unsigned char *)(&h), 8, hash);
        const uint64_t sha = *((uint64_t *)(&hash[7]));
        bloom_update(bfs[z][i], sha);
      }
    }
    bts[z] = bloomtable_build(bfs[z], xcap);
    assert(bts[z]);
  }

  // bc
  const int rawfd = open("/tmp/bctest", O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 00666);
  assert(rawfd >= 0);
  bcs = bloomcontainer_build(bts[0], rawfd, 0, &stat);
  assert(bcs);
  for (uint64_t z = 1; z < max_level; z++) {
    bcs = bloomcontainer_update(cm, bcs, bts[z], &stat);
  }

  printf("bloomcluster: nr_write_bc %lu, bc_size %lu, war %lf\n", stat.nr_write_bc, bcs->nr_index, stat.nr_write_bc * 1.0 / bcs->nr_index);

  uint64_t match=0;
  uint64_t nomatch =0;
  for (uint64_t i = 0; i < xcap; i++) {
    for (uint64_t j = 0; j < 64; j++) {
      uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
      uint8_t bitmap2[max_level] __attribute__ ((aligned(8))) = {0};

      const uint64_t z = random_uint64() % max_level;
      const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
      SHA1((const unsigned char *)(&h), 8, hash);
      const uint64_t sha = *((uint64_t *)(&hash[7]));
      const uint8_t m = bloomcontainer_match(bcs, i, sha, bitmap);
      assert(testfound(bitmap, max_level));
      const uint8_t n = bloomcontainer_match(bcs, i, sha+1, bitmap2);
      if (testfound(bitmap2, max_level)) match ++; else nomatch++;
    }
  }
  printf("bloomcluster: match %" PRIu64 ", nomatch %" PRIu64 " (m/n should < 1%%)\n", match, nomatch);
  uint64_t total = 65533;
  uint64_t read_sizes = 0;
  for (uint64_t i = 0; i < total; i++) {
    uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
    const uint64_t sha = random_uint64();
    uint64_t inx = random_uint64() % xcap;
    read_sizes += bloomcontainer_match(bcs, inx, sha, bitmap);
    if (testfound(bitmap, max_level)) match ++; else nomatch++;
  }
  printf("bloomcluster: fpr %lf, match %lu in total %lu, avg read_size %lf\n", match * 1.0 / total, match, total, read_sizes * 1.0 / total);
}

// test bloom-container
  void
segmentcontainerperf(void)
{
  const uint64_t xcap = TABLE_MAX_BARRELS; // # of barrels
  const uint64_t max_level = 200;
  const uint64_t nr_keys = 64;
  struct Mempool *mp = mempool_new(xcap * 4096 * max_level);
  struct BloomFilterGroup *bfs[max_level][xcap];
  struct BloomGroupTable *bts[max_level];
  struct SegmentBloomContainer *bcs;
  uint8_t hash[20];
  struct Stat stat;
  bzero(&stat, sizeof(stat));

  const char * const raw_fn = "/tmp/raw_test";
  uint64_t cap = UINT64_C(1024 * 1024) * max_level * 64;

  // create
  struct ContainerMap * const cm = containermap_create(raw_fn, cap);
  assert(cm);

  // bf & bt
  for (uint64_t z = 0; z < max_level; z++) { // level
    for (uint64_t i = 0; i < xcap; i++) { // index
      uint64_t hvs[1024];
      for (uint64_t j = 0; j < nr_keys; j++) { // key id
        const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
        SHA1((const unsigned char *)(&h), 8, hash);
        const uint64_t sha = *((uint64_t *)(&hash[7]));
        hvs[j] = sha;
      }
      bfs[z][i] = bloom_create_update(nr_keys, hvs, mp);
    }
    bts[z] = bloomgrouptable_build(bfs[z], xcap);
    for (uint64_t j = 0; j < nr_keys; j++) { // key id
      uint64_t i = random_uint64() % xcap;
      const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
      SHA1((const unsigned char *)(&h), 8, hash);
      const uint64_t sha = *((uint64_t *)(&hash[7]));
      assert(bloomgrouptable_match(bts[z], i, sha));
    }
    assert(bts[z]);
  }

  // bc
  const int rawfd = open("/tmp/bctest", O_CREAT | O_TRUNC | O_RDWR | O_LARGEFILE, 00666);
  assert(rawfd >= 0);
  struct BloomGroupTable * tmp_bts[32];
  tmp_bts[0] = bts[0];

  bcs = segmentbloomcontainer_build(cm, NULL, tmp_bts, 1, &stat);
  assert(bcs);
  for (uint64_t z = 1; z < max_level; z++) {
    tmp_bts[0] = bts[z];
    bcs = segmentbloomcontainer_update(cm, bcs, tmp_bts, 1, &stat);
  }

  uint64_t nr_index = 0;
  for (uint32_t i = 0; i <= bcs->cur_segment; i++) {
    nr_index += bcs->nr_index[i];
  }

  printf("segmentbloomcluster: nr_write_bc %lu, bc_size %lu, war %lf\n", stat.nr_write_bc, nr_index, stat.nr_write_bc * 1.0 / nr_index);

  uint64_t match=0;
  uint64_t nomatch =0;
  for (uint64_t i = 0; i < xcap; i++) {
    for (uint64_t j = 0; j < 64; j++) {
      uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
      uint8_t bitmap2[max_level] __attribute__ ((aligned(8))) = {0};

      const uint64_t z = random_uint64() % max_level;
      const uint64_t h = i + (j << 20) + (j << 30) + (j << 40) + (z << 50);
      SHA1((const unsigned char *)(&h), 8, hash);
      const uint64_t sha = *((uint64_t *)(&hash[7]));
      const uint8_t m = segmentbloomcontainer_match(bcs, i, sha, bitmap);
      assert(testfound(bitmap, max_level));
      const uint8_t n = segmentbloomcontainer_match(bcs, i, sha+1, bitmap2);
      if (testfound(bitmap2, max_level)) match ++; else nomatch++;
    }
  }
  printf("segmentbloomcluster: match %" PRIu64 ", nomatch %" PRIu64 " (m/n should < 1%%)\n", match, nomatch);
  uint64_t total = 65533;
  uint64_t read_sizes = 0;
  for (uint64_t i = 0; i < total; i++) {
    uint8_t bitmap[max_level] __attribute__ ((aligned(8))) = {0};
    const uint64_t sha = random_uint64();
    uint64_t inx = random_uint64() % xcap;
    read_sizes += segmentbloomcontainer_match(bcs, inx, sha, bitmap);
    if (testfound(bitmap, max_level)) match ++; else nomatch++;
  }
  printf("segmentbloomcluster: fpr %lf, match %lu in total %lu, avg read_size %lf\n", match * 1.0 / total, match, total, read_sizes * 1.0 / total);

}

  int
main(int argc, char **argv)
{
  (void)argc;
  (void)argv;

  // uncached_probe_test();
  // false_positive_test();
  pbf_false_positive_test();
  // multi_level_false_positive_test();
  // containertest();
  containerperf();
  segmentcontainerperf();
}
