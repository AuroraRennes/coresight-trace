/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Dispatch points for the ptm2human/Stalker ETMv4 decoder in
 * stalker-decoder/.
 * Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933 */

#include "stalker.h"

#include <stdio.h>
#include <stdlib.h>

#include "stalker_adapter.h"

static size_t stalker_dump_limit = 0;
static bool stalker_diag = false;

static void stalker_debug_dump_capture(const void *buf, size_t buf_size)
{
  const unsigned char *b = (const unsigned char *)buf;
  size_t n = buf_size < stalker_dump_limit ? buf_size : stalker_dump_limit;
  size_t k;

  fprintf(stderr, "[STALKER-DECODER] first %zu bytes:", n);
  for (k = 0; k < n; k++) fprintf(stderr, " %02x", b[k]);
  fprintf(stderr, "\n");
}

/* nonzero_bytes cannot tell "the ETM emitted nothing" from "every address
 * packet was rejected"; the counters can. map_hash (FNV-1a over the whole
 * bitmap) separates "same coverage" from "same number of different bytes",
 * which is what any determinism measurement on this backend needs. */
static void stalker_debug_report(const unsigned char *trace_bitmap,
                                 unsigned int trace_bitmap_size,
                                 size_t buf_size)
{
  unsigned int i, nonzero = 0;
  unsigned long long map_hash = 1469598103934665603ULL; /* FNV-1a basis */
  struct stalker_decode_stats st;

  for (i = 0; i < trace_bitmap_size; i++) {
    if (trace_bitmap[i]) nonzero++;
    map_hash = (map_hash ^ trace_bitmap[i]) * 1099511628211ULL;
  }
  fprintf(stderr, "[STALKER-DECODER] nonzero_bytes=%u/%u map_hash=%016llx\n",
          nonzero, trace_bitmap_size, map_hash);

  stalker_decoder_get_stats(&st);
  fprintf(stderr,
          "[STALKER-DIAG] buf=%zu addr_pkts=%llu committed=%llu "
          "bflag0=%llu out_of_range=%llu irq_swallowed=%llu atoms=%llu "
          "branches=%llu overflow=%llu exceptions=%llu text=0x%llx-0x%llx\n",
          buf_size, st.addr_pkt_nums, st.addr_pkt_committed,
          st.addr_pkt_branchflag0, st.addr_pkt_out_of_range,
          st.addr_pkt_irq_swallowed, st.atom_nums, st.branch_nums,
          st.overflow_nums, st.exception_nums, st.text_start_addr,
          st.text_end_addr);
}

int stalker_setup(pid_t pid, struct map_info *map_info, int map_info_num)
{
  /* initialize decoder */
  if (stalker_decoder_init(pid, map_info, map_info_num) < 0) {
    fprintf(stderr, "stalker_decoder_init() failed\n");
    return -1;
  }

  /* env variables */
  const char *dump = getenv("AFLCS_STALKER_DUMP_BYTES");
  stalker_dump_limit = dump ? (size_t)atoi(dump) : 0;
  stalker_diag = getenv("AFLCS_STALKER_DIAG") != NULL;

  /* bb_mode=0 to match the ETM by default (reprogrammed by the proxy) */
  stalker_decoder_set_bb_mode(0);

  return 0;
}

void stalker_set_bb_mode(int bb_mode)
{
  stalker_decoder_set_bb_mode(bb_mode);
}

int stalker_reset(void)
{
  /* Nothing to do: this decoder needs no disassembly or mem_map, and resets
   * its per-exec state inside stalker_decode_trace(). */
  return 0;
}

int stalker_run(unsigned char *trace_bitmap, unsigned int trace_bitmap_size,
                void *buf, size_t buf_size, bool *did_overflow)
{
  if (stalker_dump_limit) {
    stalker_debug_dump_capture(buf, buf_size);
  }

  if (stalker_decode_trace(trace_bitmap, trace_bitmap_size, buf, buf_size) < 0) {
    return -1;
  }

  if (stalker_diag) {
    stalker_debug_report(trace_bitmap, trace_bitmap_size, buf_size);
  }

  if (stalker_decode_did_overflow()) {
    *did_overflow = true;
    fprintf(stderr, "[DECODER] overflow packet observed, truncating decode for this exec\n");
    return -1;
  }

  return 0;
}

int stalker_fini(void)
{
  return 0;
}

void stalker_configure_addr_range(struct map_info *range,
                                  cs_etmv4_config_t *tconfig)
{
  /* This decoder has no per-library disambiguation, so config.c's default
   * loop over every mapped range would fold libc and ld.so into the coverage
   * hash and inflate trace volume enough to overflow the ETR. Filter on the
   * main binary only, matching stalker_decoder_init()'s map_info[idx] match.
   * map_info[] itself is untouched. */
  set_etmv4_addr_range(&range[0], &tconfig->addr_comps[0], 0);
  tconfig->addr_comps_acc_mask |= 0x3;
  tconfig->viiectlr |= 1;
}
