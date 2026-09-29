/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Stalker's hybrid coverage (etm_mode == 3), moved from afl-fuzz into the
 * proxy. Every input runs in path mode first; only when its path bitmap is new
 * is it re-run with branch broadcast, and that edge bitmap is what AFL++ sees.
 * Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933 */

#ifndef CS_TRACE_HYBRID_H
#define CS_TRACE_HYBRID_H

#include <stddef.h>

typedef enum {
  HYBRID_DISCARD = 0, /* no new path: AFL++ must see no new edges */
  HYBRID_CONFIRM,     /* new path: re-run with branch broadcast */
} hybrid_verdict_t;

void hybrid_init(size_t map_size);

/* After the path pass. On HYBRID_DISCARD the map has been replaced with the
 * edge map last confirmed for this path, or zeroed if there is none. On
 * HYBRID_CONFIRM the path map is kept aside for hybrid_after_confirm(). */
hybrid_verdict_t hybrid_after_path(unsigned char *map, int overflowed);

/* After the edge (branch-broadcast) pass; the map is left as decoded */
void hybrid_after_confirm(const unsigned char *map, int overflowed);

#endif /* CS_TRACE_HYBRID_H */
