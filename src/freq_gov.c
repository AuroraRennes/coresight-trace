/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* Overflow-aware CPU frequency governor, reimplemented from the ACFMM algorithm
 * described by the Stalker authors and extended. One search over the available
 * frequencies on the board (rather than 10KHz steps).
 * Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "freq_gov.h"

#define FREQ_INTERVAL     1000
#define MIN_FREQ_INTERVAL 100
#define MAX_FREQ_INTERVAL 1000

/* ============== STATE ============== */

static int g_cpu = 0;
static unsigned long long system_min_cpufreq = 0;
static unsigned long long system_max_cpufreq = 0;

/* Available frequencies on the board, rather than using 10kHz steps
 * like Stalker */
static unsigned long long freq_table[64];
static int freq_table_num = 0;

/* Per-mode search state. cur_idx is the live position; the rest is evidence
 * accumulated about it. */
static int cur_idx[FREQ_MODE_COUNT];
static int opt_idx_sum[FREQ_MODE_COUNT];
static unsigned long long stable_nums[FREQ_MODE_COUNT];
static unsigned long long non_overflow_nums[FREQ_MODE_COUNT];
static unsigned long long total_execs[FREQ_MODE_COUNT];
static unsigned long long total_overflow_execs[FREQ_MODE_COUNT];

/* Shared adaptive window: Stalker recomputes this from atom-mode's
 * cumulative exec/overflow ratio alone and uses the single result for
 * both modes' non_overflow_nums thresholds. */
static unsigned long long freq_interval = MIN_FREQ_INTERVAL;

/* AFLCS_COV=edge, i.e. upstream's etm_mode == 1: the addr pass runs alone and
 * atom mode never executes. Stalker gates both the initial value and every
 * update of freq_interval on this, so in edge mode the window stays at
 * MIN_FREQ_INTERVAL for the whole run. */
static int addr_only_mode = 0;

/* AFLCS_FREQ_DIAG=1 logs every frequency write with its origin. */
static int freq_diag = 0;

/* Set by freq_gov_force_min(), consumed by the next freq_gov_apply(). */
static int force_min_pending = 0;

/* Saved values to restore */
static char saved_governor[32] = {0};

static struct {
  char path[160];
  char val[32];
} restore_ops[3];

static int restore_op_num = 0;

/* ============== SYSFS ============== */

static void write_sysfs(const char *file_name, unsigned long long val)
{
  char path[128];
  char content[32];
  int fd, len;

  snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/%s",
           g_cpu, file_name);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    perror(path);
    return;
  }
  len = snprintf(content, sizeof(content), "%llu", val);
  if (write(fd, content, (size_t)len) < 0) {
    perror(path);
  }
  close(fd);
}

static void write_sysfs_str(const char *file_name, const char *val)
{
  char path[128];
  int fd;

  snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/%s",
           g_cpu, file_name);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    perror(path);
    return;
  }
  if (write(fd, val, strlen(val)) < 0) {
    perror(path);
  }
  close(fd);
}

static unsigned long long read_sysfs(const char *file_name)
{
  char path[128];
  unsigned long long val = 0;
  FILE *fp;

  snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/%s",
           g_cpu, file_name);
  fp = fopen(path, "r");
  if (!fp) {
    perror(path);
    return 0;
  }
  if (fscanf(fp, "%llu", &val) != 1) {
    val = 0;
  }
  fclose(fp);
  return val;
}

/* ============== FREQUENCY TABLE ============== */

/* Reads scaling_available_frequencies for available frequencies */
static void read_available_frequencies(void)
{
  char path[128];
  FILE *fp;
  int i, j;

  freq_table_num = 0;

  /* Parse available frequencies */
  snprintf(path, sizeof(path),
           "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_available_frequencies",
           g_cpu);
  fp = fopen(path, "r");
  if (fp) {
    unsigned long long f;
    while (freq_table_num < (int)(sizeof(freq_table) / sizeof(freq_table[0])) &&
           fscanf(fp, "%llu", &f) == 1) {
      if (f < system_min_cpufreq || f > system_max_cpufreq) continue;
      freq_table[freq_table_num++] = f;
    }
    fclose(fp);
  }

  /* No table, use hardware bounds */
  if (freq_table_num == 0) {
    freq_table[0] = system_min_cpufreq;
    freq_table[1] = system_max_cpufreq;
    freq_table_num = 2;
  }

  /* Sort ascending: every step below assumes it, and the file is not
   * guaranteed sorted (cpufreq-dt lists ascending, other drivers descending). */
  for (i = 1; i < freq_table_num; i++) {
    unsigned long long key = freq_table[i];
    for (j = i - 1; j >= 0 && freq_table[j] > key; j--) {
      freq_table[j + 1] = freq_table[j];
    }
    freq_table[j + 1] = key;
  }
}

/* Last value set_freq() wrote, or 0 when the hardware state is unknown.
 * Guards the redundant-write skip below. */
static unsigned long long last_set_freq = 0;

/* Pin the frequency to `target`; write order matters for it to be accepted.
 * Skipped when already there: four sysfs writes per call is not free. */
static void set_freq(unsigned long long target, const char *why)
{
  if (target == last_set_freq) {
    if (freq_diag) {
      fprintf(stderr, "[FREQ_GOV] set %llu kHz (%s) skipped, already set\n",
              target, why);
    }
    return;
  }

  if (freq_diag) {
    fprintf(stderr, "[FREQ_GOV] set %llu kHz (%s)\n", target, why);
  }

  write_sysfs("scaling_min_freq", system_min_cpufreq);
  write_sysfs("scaling_max_freq", target);
  write_sysfs("scaling_min_freq", target);
  write_sysfs("scaling_setspeed", target);

  last_set_freq = target;
}

/* ============== SAVE/RESTORE ============== */

static void add_restore_op(const char *file_name, const char *val)
{
  if (restore_op_num >= (int)(sizeof(restore_ops) / sizeof(restore_ops[0]))) return;
  snprintf(restore_ops[restore_op_num].path, sizeof(restore_ops[0].path),
           "/sys/devices/system/cpu/cpu%d/cpufreq/%s", g_cpu, file_name);
  snprintf(restore_ops[restore_op_num].val, sizeof(restore_ops[0].val), "%s", val);
  restore_op_num++;
}

/* Restore with base frequency on exit/signal. Paths and values are preformatted
 * by add_restore_op() at init */
static void freq_gov_restore_system(void)
{
  int i;

  for (i = 0; i < restore_op_num; i++) {
    int fd = open(restore_ops[i].path, O_WRONLY);
    if (fd < 0) continue;
    (void)!write(fd, restore_ops[i].val, strlen(restore_ops[i].val));
    close(fd);
  }

  /* Bounds and governor just moved; the last set_freq() no longer applies. */
  last_set_freq = 0;
}

/* Signal hooking to restore base frequency */
static void freq_gov_signal_restore(int sig)
{
  freq_gov_restore_system();
  signal(sig, SIG_DFL);
  raise(sig);
}

static void freq_gov_hook_signal(int sig)
{
  if (signal(sig, SIG_IGN) == SIG_IGN) return; /* deliberately ignored */
  signal(sig, freq_gov_signal_restore);
}

/* ============== REPORTING ============== */

/* Stable frequency for a mode, rounded to the nearest step */
static unsigned long long opt_freq(freq_mode_t mode)
{
  int idx;

  if (!stable_nums[mode]) return 0;
  idx = (int)(((unsigned long long)opt_idx_sum[mode] + stable_nums[mode] / 2) /
              stable_nums[mode]);
  if (idx >= freq_table_num) idx = freq_table_num - 1;
  return freq_table[idx];
}

/* Report print for a given mode */
static void freq_gov_report(void)
{
  int mode;

  if (!freq_diag) return;

  for (mode = 0; mode < FREQ_MODE_COUNT; mode++) {
    if (!total_execs[mode]) continue;
    fprintf(stderr,
            "[FREQ_GOV] mode=%d summary: %llu execs, %llu overflowed, "
            "settled %llu kHz over %llu stable windows, final %llu kHz\n",
            mode, total_execs[mode], total_overflow_execs[mode],
            opt_freq(mode), stable_nums[mode], freq_table[cur_idx[mode]]);
  }
}

/* ============== LIFECYCLE ============== */

/* Initialization of the frequency governor */
void freq_gov_init(int cpu, int addr_only)
{
  int mode;
  char path[128];
  FILE *fp;

  g_cpu = cpu;
  addr_only_mode = addr_only;

  system_max_cpufreq = read_sysfs("cpuinfo_max_freq");
  system_min_cpufreq = read_sysfs("cpuinfo_min_freq");
  read_available_frequencies();
  freq_diag = getenv("AFLCS_FREQ_DIAG") != NULL;

  /* Save previous governor */
  snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor",
           g_cpu);
  fp = fopen(path, "r");
  if (fp) {
    if (fscanf(fp, "%31s", saved_governor) != 1) saved_governor[0] = '\0';
    fclose(fp);
  }

  /* Restore targets at the hardware bounds */
  if (system_min_cpufreq) {
    char v[32];
    snprintf(v, sizeof(v), "%llu", system_min_cpufreq);
    add_restore_op("scaling_min_freq", v);
  }
  if (system_max_cpufreq) {
    char v[32];
    snprintf(v, sizeof(v), "%llu", system_max_cpufreq);
    add_restore_op("scaling_max_freq", v);
  }
  if (saved_governor[0]) add_restore_op("scaling_governor", saved_governor);

  /* Hook on signals and exit */
  atexit(freq_gov_restore_system);
  atexit(freq_gov_report);
  freq_gov_hook_signal(SIGTERM);
  freq_gov_hook_signal(SIGINT);
  freq_gov_hook_signal(SIGHUP);

  /* userspace, so scaling_setspeed pins the frequency directly */
  write_sysfs_str("scaling_governor", "userspace");
  last_set_freq = 0; /* governor just changed, force the next set_freq through */

  /* Initialize stats for each mode, starting at max freq */
  for (mode = 0; mode < FREQ_MODE_COUNT; mode++) {
    cur_idx[mode] = freq_table_num - 1;
    opt_idx_sum[mode] = 0;
    stable_nums[mode] = 0;
    non_overflow_nums[mode] = 0;
    total_execs[mode] = 0;
    total_overflow_execs[mode] = 0;
  }
  /* Matching Stalker on path */
  freq_interval = addr_only_mode ? MIN_FREQ_INTERVAL : FREQ_INTERVAL;

  fprintf(stderr,
          "[FREQ_GOV] cpu%d system_min=%llu system_max=%llu kHz, %d OPPs, "
          "addr_only=%d freq_interval=%llu%s\n",
          g_cpu, system_min_cpufreq, system_max_cpufreq, freq_table_num,
          addr_only_mode, freq_interval,
          addr_only_mode ? " (fixed)" : " (adaptive)");
}

/* Start from the floor frequency and run until the first overflow, keeping the
 * highest rung that ran clean, once on first execution. */
void freq_gov_calibrate(freq_mode_t mode, int (*run_one_shot)(void *ctx),
                        void *ctx)
{
  int i;
  cur_idx[mode] = 0;

  for (i = 0; i < freq_table_num; i++) {
    set_freq(freq_table[i], "calibrate");
    fprintf(stderr, "[FREQ_GOV] calibrating mode=%d at %llu kHz\n", mode,
            freq_table[i]);

    /* Run the program */
    if (run_one_shot(ctx)) break;
    cur_idx[mode] = i;
  }

  fprintf(stderr, "[FREQ_GOV] calibration settled mode=%d start_freq=%llu kHz\n",
          mode, freq_table[cur_idx[mode]]);
}

/* ============== PER-EXEC ============== */

/* Apply the frequency for a given mode */
void freq_gov_apply(freq_mode_t mode)
{
  if (force_min_pending) {
    /* One forced run at the floor. cur_idx is deliberately not written: a last
     * resort for one testcase is not evidence about where the mode belongs. */
    force_min_pending = 0;
    set_freq(freq_table[0], "force_min");
    return;
  }

  set_freq(freq_table[cur_idx[mode]], "apply");
}

/* Between execs, so the proxy's own decode work does not run throttled. */
void freq_gov_restore_max(void)
{
  set_freq(system_max_cpufreq, "restore_max");
}

void freq_gov_force_min(void)
{
  force_min_pending = 1;
}

/* One exec's outcome. Called per attempt, retries included. */
void freq_gov_on_result(freq_mode_t mode, int overflowed)
{
  total_execs[mode]++;

  /* Check for overflows */
  if (overflowed) {
    total_overflow_execs[mode]++;
    if (cur_idx[mode] > 0) {
      cur_idx[mode]--;
      if (freq_diag) {
        fprintf(stderr, "[FREQ_GOV] mode=%d step DOWN to %llu kHz (overflow, execs=%llu)\n",
                (int)mode, freq_table[cur_idx[mode]], total_execs[mode]);
      }
    }
    non_overflow_nums[mode] = 0;
  } else {
    non_overflow_nums[mode]++;

    if (non_overflow_nums[mode] >= freq_interval) {
      /* Clean window: record it, check one up if possible */
      stable_nums[mode]++;
      opt_idx_sum[mode] += cur_idx[mode];

      if (cur_idx[mode] < freq_table_num - 1) {
        cur_idx[mode]++;
        if (freq_diag) {
          fprintf(stderr, "[FREQ_GOV] mode=%d step UP to %llu kHz (%llu clean, interval=%llu, execs=%llu, opt=%llu kHz over %llu windows)\n",
                  (int)mode, freq_table[cur_idx[mode]], non_overflow_nums[mode],
                  freq_interval, total_execs[mode], opt_freq(mode),
                  stable_nums[mode]);
        }
      }
      non_overflow_nums[mode] = 0;
    }
  }

  /* Shared adaptive window between all modes */
  if (!addr_only_mode && total_overflow_execs[FREQ_MODE_ATOM] > 0) {
    unsigned long long fi = (total_execs[FREQ_MODE_ATOM] /
                             total_overflow_execs[FREQ_MODE_ATOM]) / 5;
    if (fi < MIN_FREQ_INTERVAL) fi = MIN_FREQ_INTERVAL;
    else if (fi > MAX_FREQ_INTERVAL) fi = MAX_FREQ_INTERVAL;
    freq_interval = fi;
  }
}

/* ============== QUERIES ============== */

int freq_gov_should_retry(freq_mode_t mode, int overflowed, int cur_repetition_num)
{
  /* Matches Stalker's retry to fuzz only on bb mode */
  if (!overflowed) return 0;
  if (mode != FREQ_MODE_ADDR) return 0;
  if (cur_idx[FREQ_MODE_ADDR] <= 0) return 0;
  if (cur_repetition_num >= FREQ_GOV_MAX_REPETITION_NUM) return 0;
  return 1;
}

int freq_gov_at_floor(freq_mode_t mode) { return cur_idx[mode] == 0; }
