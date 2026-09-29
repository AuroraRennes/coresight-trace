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
 *   edge map last confirmed for the same path, or an empty map. Either adds no
 *   new edges, and the cached map keeps AFL++'s calibration and trimming of
 *   queue entries stable (a path determines its edges).
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

static size_t map_size;

static unsigned char *virgin_atom, *virgin_atom_real, *virgin_edge;
static unsigned char *path_cls, *path_kept, *edge_cls;
static uint32_t path_kept_cksum;
static int path_kept_overflow;

/* Upstream atom_check_up/down: a checksum is filtered once both of its halves
 * have been marked, i.e. a crude two-table Bloom filter */
static unsigned char atom_check_up[1 << 16], atom_check_down[1 << 16];

static struct {
  uint32_t cksum;
  unsigned char *map;
} cache[CACHE_SLOTS];

static unsigned long long real_execs, path_execs, queued_atom_paths;
static unsigned long long pre_real_execs, pre_virgin_bits;
static unsigned long long purge_interval = PURGE_INTERVAL_LEVEL1;
static unsigned long long purge_attempt, purge_real;

/* AFLCS_STALKER_DIAG */
static int diag;
static unsigned long long n_filtered, n_confirmed, n_new_edges, n_cache_hits;

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
  memset(virgin_atom, 0xff, size);
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

static uint32_t checksum(const unsigned char *map)
{
  uint64_t h = 0xcbf29ce484222325ULL;
  const uint64_t *w = (const uint64_t *)map;

  for (size_t i = 0; i < map_size / 8; i++) {
    h ^= w[i];
    h *= 0x100000001b3ULL;
  }
  return (uint32_t)(h ^ (h >> 32));
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
          "cache_hits=%llu purges=%llu/%llu\n",
          path_execs, n_filtered, n_confirmed, n_new_edges, n_cache_hits,
          purge_real, purge_attempt);
}

static void discard(unsigned char *map, uint32_t cksum)
{
  unsigned int slot = cksum % CACHE_SLOTS;

  if (cache[slot].map && cache[slot].cksum == cksum) {
    memcpy(map, cache[slot].map, map_size);
    n_cache_hits++;
  } else {
    memset(map, 0, map_size);
  }
}

hybrid_verdict_t hybrid_after_path(unsigned char *map, int overflowed)
{
  uint32_t cksum;

  path_execs++;
  purge_check();

  classify(path_cls, map);
  cksum = checksum(path_cls);

  if (atom_check_up[cksum >> 16] && atom_check_down[cksum & 0xffff]) {
    n_filtered++;
    discard(map, cksum);
    report();
    return HYBRID_DISCARD;
  }

  if (!has_new_bits(virgin_atom, path_cls)) {
    discard(map, cksum);
    report();
    return HYBRID_DISCARD;
  }

  queued_atom_paths++;
  memcpy(path_kept, path_cls, map_size);
  path_kept_cksum = cksum;
  path_kept_overflow = overflowed;
  n_confirmed++;
  report();
  return HYBRID_CONFIRM;
}

void hybrid_after_confirm(const unsigned char *map, int overflowed)
{
  purge_check();

  classify(edge_cls, map);

  if (has_new_bits(virgin_edge, edge_cls)) {
    has_new_bits(virgin_atom_real, path_kept);
    n_new_edges++;
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
  }
}
