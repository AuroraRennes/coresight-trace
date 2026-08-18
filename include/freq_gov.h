/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Overflow-aware CPU frequency governor, reimplemented from the ACFMM algorithm
 * described by the Stalker authors.
 * Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933 */

#ifndef CS_TRACE_FREQ_GOV_H
#define CS_TRACE_FREQ_GOV_H

typedef enum {
  FREQ_MODE_ATOM = 0,
  FREQ_MODE_ADDR = 1,
  FREQ_MODE_COUNT,
} freq_mode_t;

/* Bounded retry count, matches Stalker's max_repetition_num. */
#define FREQ_GOV_MAX_REPETITION_NUM 3

/* Reads cpuinfo_{min,max}_freq and scaling_available_frequencies for `cpu`,
 * switches the policy to the userspace governor, and stages the exit restore.
 * `addr_only` is Stalker's etm_mode == 1 (AFLCS_COV=edge): pass nonzero when the
 * addr pass runs alone, so freq_interval stays fixed instead of adapting. */
void freq_gov_init(int cpu, int addr_only);

/* Ramps up through the frequency table once at first execution */
void freq_gov_calibrate(freq_mode_t mode, int (*run_one_shot)(void *ctx),
                        void *ctx);

/* Pins scaling_{min,max}_freq/scaling_setspeed */
void freq_gov_apply(freq_mode_t mode);

/* Restore frequency */
void freq_gov_restore_max(void);

/* Reports one exec's outcome and updates `mode`'s position in the table */
void freq_gov_on_result(freq_mode_t mode, int overflowed);

/* Whether an overflowed exec in `mode` should be retried at a lower frequency */
int freq_gov_should_retry(freq_mode_t mode, int overflowed,
                          int cur_repetition_num);

/* Requests one final run pinned to system_min_cpufreq after retries are
 * exhausted */
void freq_gov_force_min(void);

/* Whether `mode` is already pinned to the lowest OPP, i.e. freq_gov_force_min()
 * would re-run at the frequency just used and learn nothing. */
int freq_gov_at_floor(freq_mode_t mode);

#endif /* CS_TRACE_FREQ_GOV_H */
