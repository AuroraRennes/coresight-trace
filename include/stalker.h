/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Declares the interface to the ptm2human/Stalker ETMv4 decoder in
 * stalker-decoder/.
 *
 * Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933 */

#ifndef CS_TRACE_STALKER_H
#define CS_TRACE_STALKER_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#include "config.h" /* cs_etmv4_config_t (transitively, via csregistration.h) */
#include "utils.h"  /* struct map_info */

/* Wrappers around stalker-decoder/'s GPLv2 adapter. Apache-2.0: only the
 * adapter's public API is called here. Compiled into STALKER_DECODER=1
 * builds only, so call sites still need an #ifdef. */

/* This backend has no decoder handle as its state lives in
 * stalker-decoder/'s globals, set up by stalker_setup() */
#define STALKER_DECODER_HANDLE ((void *)0x1)

/* Resolve the tracee's text range once, by matching /proc/<pid>/exe against
 * map_info[], and set the initial bb_mode=0 the ETM resets to. */
int stalker_setup(pid_t pid, struct map_info *map_info, int map_info_num);

/* Keep the decoder's bb_mode in sync with the hardware ETM toggle.
 * 0 = atom/path (sdbm hash), 1 = branch broadcast (address-based hash). */
void stalker_set_bb_mode(int bb_mode);

/* Per-exec decoder reset. */
int stalker_reset(void);

/* Decode buf/buf_size into trace_bitmap; report overflow via *did_overflow. */
int stalker_run(unsigned char *trace_bitmap, unsigned int trace_bitmap_size,
                void *buf, size_t buf_size, bool *did_overflow);

/* No per-decoder teardown needed. */
int stalker_fini(void);

/* Restrict the ETM's ViewInst-Include filter to range[0], the tracee itself.
 * See stalker.c for why. */
void stalker_configure_addr_range(struct map_info *range,
                                  cs_etmv4_config_t *tconfig);

#endif /* CS_TRACE_STALKER_H */
