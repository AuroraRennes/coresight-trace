/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Stalker's hybrid coverage (etm_mode == 3), reimplemented in the proxy from
 * upstream AFL-ETM's save_if_interesting() and purge_atom_coverage(). The
 * proxy keeps the maps afl-fuzz kept upstream: virgin_atom (path novelty),
 * virgin_atom_real (paths that led to new edges), a shadow of virgin_bits
 * (edge novelty, for the purge heuristic) and the atom_check_up/down checksum
 * filter, under their upstream names; upstream calls path mode "atom" mode.
 *
 * Differences from upstream, all forced by AFL++ being unmodified:
 * - A discarded input cannot be dropped, AFL++ always reads a map. It gets the
 *   edge map last confirmed for the same path, which adds no new edges and
 *   keeps AFL++'s calibration and trimming of queue entries stable (a path
 *   determines its edges). An input AFL++ has already been shown a map for
 *   gets that map again: a nondeterministic target re-run on one input
 *   (calibration) can take a path never confirmed, and an empty map there
 *   makes calibrate_case() abort with NOINST or mark the whole trace as
 *   variable. Otherwise (a fresh input whose path adds no bits) the map is
 *   empty, which is upstream's verdict without its edge pass.
 * - Calibration runs every exec in path mode, with the edge pass on
 *   the first; upstream ran half the calibration execs in each mode.
 * - purge_atom_coverage()'s exec counter counts every exec: the proxy cannot
 *   tell calibration execs, which upstream ran with count_in = 0, from fuzzing
 *   ones, so purges come somewhat earlier.
 * - No update_checksum_in_hybrid_mode() re-run at the start of each
 *   fuzz_one(); nothing here reads a per-entry path checksum.
 * - No sensitive_queue/ directory. */

#include "hybrid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Upstream afl-fuzz.c */
#define PURGE_INTERVAL_LEVEL1 3000
#define PURGE_INTERVAL_LEVEL2 7500
#define PURGE_INTERVAL_LEVEL3 15000
#define PURGE_INTERVAL_LEVEL4 30000

/* Confirmed path -> edge map, direct-mapped on the path checksum. Only answers
 * what to show AFL++ for a discarded input, never whether to confirm. */
#define CACHE_SLOTS 256

/* Input key -> edge map first shown to AFL++ for it. Calibration re-runs an
 * input back to back, so a few slots are enough. */
#define INPUT_SLOTS 64

static size_t map_size;

static unsigned char *virgin_atom, *virgin_atom_real, *virgin_edge, *virgin_missed;
static unsigned char *path_cls, *path_kept, *edge_cls;
static uint32_t path_kept_cksum;
static int path_kept_overflow;
static uint64_t path_kept_input;
static int last_filtered;  /* the last discard came from the checksum filter */

/* Upstream atom_check_up/down: a checksum is filtered once both of its halves
 * have been marked, i.e. a crude two-table Bloom filter */
static unsigned char atom_check_up[1 << 16], atom_check_down[1 << 16];

static struct {
  uint32_t cksum;
  unsigned char *map;
} cache[CACHE_SLOTS];

static struct {
  uint64_t key;
  unsigned char *map;
} inputs[INPUT_SLOTS];

static unsigned long long real_execs, path_execs, queued_atom_paths;
static unsigned long long pre_real_execs, pre_virgin_bits;
static unsigned long long purge_interval = PURGE_INTERVAL_LEVEL1;
static unsigned long long purge_attempt, purge_real;

/* AFLCS_STALKER_DIAG and hybrid_write_stats() */
static int diag;
static unsigned long long n_filtered, n_old_path, n_confirmed, n_new_edges, n_cache_hits;
static unsigned long long n_new_tuples, n_input_hits, n_empty;

/* AFLCS_HYBRID_SAMPLE: discards re-run with branch broadcast */
static unsigned long long n_sampled, n_sample_overflow, n_sample_new, n_sample_new_tuples;
static unsigned long long n_sample_new_filtered;

static const unsigned char count_class[256] = {
  [0] = 0, [1] = 1, [2] = 2, [3] = 4,
  [4 ... 7] = 8, [8 ... 15] = 16, [16 ... 31] = 32,
  [32 ... 127] = 64, [128 ... 255] = 128,
};

static void *xmalloc(size_t n)
{
  void *p = malloc(n);
  if (!p) {
    perror("hybrid: malloc");
    exit(1);
  }
  return p;
}

void hybrid_init(size_t size)
{
  map_size = size;

  virgin_atom = xmalloc(size);
  virgin_atom_real = xmalloc(size);
  virgin_edge = xmalloc(size);
  virgin_missed = xmalloc(size);
  memset(virgin_atom, 0xff, size);
  memset(virgin_missed, 0xff, size);
  memset(virgin_atom_real, 0xff, size);
  memset(virgin_edge, 0xff, size);

  path_cls = xmalloc(size);
  path_kept = xmalloc(size);
  edge_cls = xmalloc(size);

  diag = getenv("AFLCS_STALKER_DIAG") != NULL;
}

/* AFL++ classifies the map it reads, so the proxy compares a classified copy
 * and leaves the shared map raw (classification is not idempotent) */
static void classify(unsigned char *dst, const unsigned char *src)
{
  for (size_t i = 0; i < map_size; i++) dst[i] = count_class[src[i]];
}

/* Upstream hash.h's hash32() (AFL 2.52b's MurmurHash3 variant) and its
 * HASH_CONST, under the same #ifdef: the 32-bit variant on the A53 */
#define HASH_CONST 0xa5b35705

#ifdef __x86_64__

#define ROL64(_x, _r) ((((uint64_t)(_x)) << (_r)) | (((uint64_t)(_x)) >> (64 - (_r))))

static inline uint32_t hash32(const void *key, uint32_t len, uint32_t seed)
{
  const uint64_t *data = (const uint64_t *)key;
  uint64_t h1 = seed ^ len;

  len >>= 3;

  while (len--) {
    uint64_t k1 = *data++;

    k1 *= 0x87c37b91114253d5ULL;
    k1 = ROL64(k1, 31);
    k1 *= 0x4cf5ad432745937fULL;

    h1 ^= k1;
    h1 = ROL64(h1, 27);
    h1 = h1 * 5 + 0x52dce729;
  }

  h1 ^= h1 >> 33;
  h1 *= 0xff51afd7ed558ccdULL;
  h1 ^= h1 >> 33;
  h1 *= 0xc4ceb9fe1a85ec53ULL;
  h1 ^= h1 >> 33;

  return h1;
}

#else

#define ROL32(_x, _r) ((((uint32_t)(_x)) << (_r)) | (((uint32_t)(_x)) >> (32 - (_r))))

static inline uint32_t hash32(const void *key, uint32_t len, uint32_t seed)
{
  const uint32_t *data = (const uint32_t *)key;
  uint32_t h1 = seed ^ len;

  len >>= 2;

  while (len--) {
    uint32_t k1 = *data++;

    k1 *= 0xcc9e2d51;
    k1 = ROL32(k1, 15);
    k1 *= 0x1b873593;

    h1 ^= k1;
    h1 = ROL32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;
}

#endif /* ^__x86_64__ */

static uint32_t checksum(const unsigned char *map)
{
  return hash32(map, map_size, HASH_CONST);
}

/* AFL's has_new_bits(): 2 for a new tuple, 1 for a new hit count, 0 else */
static int has_new_bits(unsigned char *virgin, const unsigned char *cls)
{
  int ret = 0;

  for (size_t i = 0; i < map_size; i++) {
    if (cls[i] & virgin[i]) {
      ret = (virgin[i] == 0xff) ? 2 : (ret > 1 ? ret : 1);
      virgin[i] &= ~cls[i];
    }
  }
  return ret;
}

/* has_new_bits() that leaves virgin as it is */
static int peek_new_bits(const unsigned char *virgin, const unsigned char *cls)
{
  int ret = 0;

  for (size_t i = 0; i < map_size; i++) {
    if (cls[i] & virgin[i]) {
      if (virgin[i] == 0xff) return 2;
      ret = 1;
    }
  }
  return ret;
}

static unsigned long long count_non_255_bytes(const unsigned char *map)
{
  unsigned long long n = 0;

  for (size_t i = 0; i < map_size; i++) n += map[i] != 0xff;
  return n;
}

/* Upstream purge_atom_coverage(), called once per counted exec. When edge
 * coverage stalls, or most of virgin_atom is paths that led nowhere, forget
 * them so their paths can be confirmed again. */
static void purge_check(void)
{
  real_execs++;
  if (real_execs - pre_real_execs < purge_interval) return;

  if (count_non_255_bytes(virgin_edge) <= 1.01 * pre_virgin_bits ||
      count_non_255_bytes(virgin_atom_real) * 2 < count_non_255_bytes(virgin_atom)) {
    memcpy(virgin_atom, virgin_atom_real, map_size);
    purge_real++;

    if (purge_real > 20) {
      if (queued_atom_paths < 0.1 * path_execs)
        purge_interval = PURGE_INTERVAL_LEVEL1;
      else if (queued_atom_paths < 0.25 * path_execs)
        purge_interval = PURGE_INTERVAL_LEVEL2;
      else if (queued_atom_paths < 0.5 * path_execs)
        purge_interval = PURGE_INTERVAL_LEVEL3;
      else
        purge_interval = PURGE_INTERVAL_LEVEL4;
      purge_interval = purge_interval * (purge_attempt * 1.0 / purge_real);
      if (purge_interval > PURGE_INTERVAL_LEVEL4)
        purge_interval = PURGE_INTERVAL_LEVEL4;
    }

    if (diag) {
      fprintf(stderr, "[HYBRID] purge #%llu at exec %llu, next interval %llu\n",
              purge_real, real_execs, purge_interval);
    }
  }

  pre_virgin_bits = count_non_255_bytes(virgin_edge);
  pre_real_execs = real_execs;
  purge_attempt++;
}

static void report(void)
{
  if (!diag || path_execs % 1000) return;

  fprintf(stderr,
          "[HYBRID] path=%llu filtered=%llu confirmed=%llu new_edges=%llu "
          "cache_hits=%llu input_hits=%llu empty=%llu purges=%llu/%llu\n",
          path_execs, n_filtered, n_confirmed, n_new_edges, n_cache_hits,
          n_input_hits, n_empty, purge_real, purge_attempt);
}

/* Remember the map AFL++ is shown for this input, unless one already is */
static void remember_input(uint64_t key, const unsigned char *map)
{
  unsigned int slot = key % INPUT_SLOTS;

  if (!key || (inputs[slot].map && inputs[slot].key == key)) return;
  if (!inputs[slot].map) inputs[slot].map = xmalloc(map_size);
  memcpy(inputs[slot].map, map, map_size);
  inputs[slot].key = key;
}

/* Show AFL++ the edge map it was shown for this input, so re-runs of one input
 * read the same map whatever path they take, or the one cached for this path */
static void discard(unsigned char *map, uint32_t cksum, uint64_t key)
{
  unsigned int slot = cksum % CACHE_SLOTS;
  unsigned int islot = key % INPUT_SLOTS;

  if (key && inputs[islot].map && inputs[islot].key == key) {
    memcpy(map, inputs[islot].map, map_size);
    n_input_hits++;
  } else if (cache[slot].map && cache[slot].cksum == cksum) {
    memcpy(map, cache[slot].map, map_size);
    remember_input(key, map);
    n_cache_hits++;
  } else {
    memset(map, 0, map_size);
    n_empty++;
  }
}

hybrid_verdict_t hybrid_after_path(unsigned char *map, int overflowed,
                                   uint64_t input_key)
{
  uint32_t cksum;

  path_execs++;
  purge_check();

  /* Upstream's run_target() hashes the raw counts, before classify_counts() */
  cksum = checksum(map);
  classify(path_cls, map);

  last_filtered = 0;
  if (atom_check_up[cksum >> 16] && atom_check_down[cksum & 0xffff]) {
    n_filtered++;
    last_filtered = 1;
    discard(map, cksum, input_key);
    report();
    return HYBRID_DISCARD;
  }

  if (!has_new_bits(virgin_atom, path_cls)) {
    n_old_path++;
    discard(map, cksum, input_key);
    report();
    return HYBRID_DISCARD;
  }

  queued_atom_paths++;
  memcpy(path_kept, path_cls, map_size);
  path_kept_cksum = cksum;
  path_kept_overflow = overflowed;
  path_kept_input = input_key;
  n_confirmed++;
  report();
  return HYBRID_CONFIRM;
}

void hybrid_after_confirm(const unsigned char *map, int overflowed)
{
  purge_check();

  classify(edge_cls, map);

  int new_bits = has_new_bits(virgin_edge, edge_cls);

  if (new_bits) {
    has_new_bits(virgin_atom_real, path_kept);
    n_new_edges++;
    if (new_bits == 2) n_new_tuples++;
  } else {
    atom_check_up[path_kept_cksum >> 16] = 1;
    atom_check_down[path_kept_cksum & 0xffff] = 1;
  }

  /* A truncated trace on either pass would pin the wrong edges to this path */
  if (!overflowed && !path_kept_overflow) {
    unsigned int slot = path_kept_cksum % CACHE_SLOTS;

    if (!cache[slot].map) cache[slot].map = xmalloc(map_size);
    memcpy(cache[slot].map, map, map_size);
    cache[slot].cksum = path_kept_cksum;
    remember_input(path_kept_input, map);
  }
}

void hybrid_after_sample(const unsigned char *map, int overflowed)
{
  int new_bits;

  if (overflowed) {
    n_sample_overflow++;
    return;
  }
  n_sampled++;

  classify(edge_cls, map);
  new_bits = peek_new_bits(virgin_edge, edge_cls);
  if (new_bits) {
    n_sample_new++;
    if (new_bits == 2) n_sample_new_tuples++;
    if (last_filtered) n_sample_new_filtered++;
  }
  has_new_bits(virgin_missed, edge_cls);
}

/* Tuples some sampled discard reached that no confirm has shown AFL++ yet */
static unsigned long long count_missed_tuples(void)
{
  unsigned long long n = 0;

  for (size_t i = 0; i < map_size; i++)
    n += virgin_missed[i] != 0xff && virgin_edge[i] == 0xff;
  return n;
}

void hybrid_write_stats(FILE *fp)
{
  fprintf(fp,
          "hybrid_path_execs  : %llu\n"
          "hybrid_filtered    : %llu\n"
          "hybrid_old_path    : %llu\n"
          "hybrid_confirmed   : %llu\n"
          "hybrid_new_edges   : %llu\n"
          "hybrid_new_tuples  : %llu\n"
          "hybrid_input_hits  : %llu\n"
          "hybrid_cache_hits  : %llu\n"
          "hybrid_empty       : %llu\n"
          "hybrid_purges      : %llu/%llu\n",
          path_execs, n_filtered, n_old_path, n_confirmed, n_new_edges, n_new_tuples,
          n_input_hits, n_cache_hits, n_empty, purge_real, purge_attempt);
  if (!n_sampled && !n_sample_overflow) return;
  fprintf(fp,
          "sample_execs       : %llu\n"
          "sample_overflow    : %llu\n"
          "sample_new_edges   : %llu\n"
          "sample_new_tuples  : %llu\n"
          "sample_new_filtered: %llu\n"
          "sample_missed_tuples: %llu\n",
          n_sampled, n_sample_overflow, n_sample_new, n_sample_new_tuples,
          n_sample_new_filtered, count_missed_tuples());
}
