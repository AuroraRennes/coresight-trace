/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2019-2020 AFLplusplus Project. All rights reserved. */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef __ANDROID__
#include "afl/android-ashmem.h"
#endif
#include "afl/config.h"
#include "afl/types.h"
#include "afl/debug.h"

#include "config.h"
#include "common.h"
#ifdef AFLCS_STALKER_DECODER
#include "freq_gov.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <fcntl.h>

#define AFLCS_PROXY_NAME "afl-cs-proxy"
#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)

char *__afl_proxy_name = AFLCS_PROXY_NAME;

s32 fsrv_pid = -1;
s32 proxy_ctl_fd = -1;
s32 proxy_st_fd = -1;
u8 first_run = 1;

#ifdef EXEC_COUNT
u32 exec_count = 0;
#endif

#ifdef AFLCS_STALKER_DECODER
static unsigned long long total_exec_count = 0;
static unsigned long long overflow_exec_count = 0;
/* Upfront calibration, matching Stalker's cpu_frequency_analysis(). Seeds
 * rarely overflow, so the ramp is usually inert; AFLCS_FREQ_CALIBRATE=0 skips it. */
static int needs_calibration = 1;
#endif /* AFLCS_STALKER_DECODER */

/* TODO: Remove extern variables. */
extern int udmabuf_num;
extern bool decoding_on;
extern unsigned char *trace_bitmap;
extern unsigned int trace_bitmap_size;
extern cov_type_t cov_type;
#ifdef AFLCS_STALKER_DECODER
extern int trace_cpu;
#endif
char *ld_forksrv_path;

#ifdef AFLCS_STALKER_DECODER
static freq_mode_t current_freq_mode(void)
{
  return (cov_type == path_cov) ? FREQ_MODE_ATOM : FREQ_MODE_ADDR;
}
#endif

/* Error reporting to forkserver controller */

void send_forkserver_error(int error)
{
  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;
}

/* SHM setup. */

static void __afl_map_shm(void)
{
  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {
    u32 val = atoi(ptr);
    if (val > 0) trace_bitmap_size = val;
  }

  if (trace_bitmap_size > MAP_SIZE) {
    if (trace_bitmap_size > FS_OPT_MAX_MAPSIZE) {
      fprintf(stderr,
              "Error: %s *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_proxy_name, trace_bitmap_size);
      if (id_str) {
        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);
      }

    } else {
      fprintf(stderr,
              "Warning: %s will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_proxy_name, trace_bitmap_size);
    }
  }

  if (id_str) {
#ifdef USEMMAP
    const char *shm_file_path = id_str;
    int shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {
      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);
    }

    /* map the shared memory segment to the address space of the process */
    shm_base = mmap(0, trace_bitmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    shm_fd, 0);

    if (shm_base == MAP_FAILED) {
      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);
    }

    trace_bitmap = shm_base;
#else
    u32 shm_id = atoi(id_str);

    trace_bitmap = shmat(shm_id, 0, 0);

#endif

    if (trace_bitmap == (void *)-1) {
      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);
    }

    /* Write something into the bitmap so that the parent doesn't give up */

    trace_bitmap[0] = 1;
  }
}

/* Fork server logic. */

static void __afl_start_forkserver(char *argv[])
{
  u8 tmp[4] = {0, 0, 0, 0};
  u32 status = 0;
  int st_pipe[2], ctl_pipe[2];

  if (pipe(st_pipe) || pipe(ctl_pipe)) {
    PFATAL("pipe() failed");
  }

  fsrv_pid = fork();
  if (fsrv_pid < 0) {
    PFATAL("fork() failed");
  }

  if (!fsrv_pid) {
    /* Child Process */

    if (dup2(ctl_pipe[0], AFLCS_FORKSRV_FD) < 0) {
      PFATAL("dup2() failed");
    }
    if (dup2(st_pipe[1], AFLCS_FORKSRV_FD + 1) < 0) {
      PFATAL("dup2() failed");
    }

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);

    char *ld_preload = "LD_PRELOAD=";
    char *ld_library_path = "LD_LIBRARY_PATH=";

    char *cs_ld_preload = getenv("CS_LD_PRELOAD");
    char *cs_ld_lib_path = getenv("CS_LD_LIBRARY_PATH");
    char *cs_defer_forksrv = getenv("CS_DEFER_FORKSRV");

    if(cs_ld_preload != NULL){
      ld_preload = append_string(ld_preload,cs_ld_preload);
    }
    if(ld_library_path != NULL){
      ld_library_path = append_string(ld_library_path, cs_ld_lib_path);
    }

    if(cs_defer_forksrv == NULL){
      ld_preload = append_string(ld_preload,ld_forksrv_path);
    }

    char* envp[] = {"__CS_PROXY=1", ld_preload, ld_library_path, NULL};

    DEBUGF("Try run target: %s \n with envp=\n", argv[0]);
      for (int i = 0; envp[i] != NULL; i++) {
          DEBUGF("%s\n", envp[i]);
      }
    execve(argv[0], argv, envp);

    FATAL("Error: execv to target failed\n");
  }

  /* Parent Process */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  proxy_ctl_fd = ctl_pipe[1];
  proxy_st_fd = st_pipe[0];

  if (read(proxy_st_fd, &tmp, 4) != 4) {
    PFATAL("read() failed");
  }
  memcpy(&status, tmp, 4);

  if (!status) {
    if (trace_bitmap_size <= FS_OPT_MAX_MAPSIZE)
      status |= (FS_OPT_SET_MAPSIZE(trace_bitmap_size) | FS_OPT_MAPSIZE);
    if (status) status |= (FS_OPT_ENABLED);
    memcpy(tmp, &status, 4);
  }

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    PFATAL("write() failed");
  }
}

#ifdef AFLCS_STALKER_DECODER
/* Fresh child via the inner protocol only, never AFL++'s outer pipes. Safe to
 * repeat on one testcase until __afl_end_testcase(); used for hidden retries. */
static s32 fork_fresh_child(void)
{
  s32 was_killed = 0;
  s32 child_pid;

  if (write(proxy_ctl_fd, &was_killed, 4) != 4) return -1;
  if (read(proxy_st_fd, &child_pid, 4) != 4) return -1;

  return child_pid;
}
#endif /* AFLCS_STALKER_DECODER */

/* Arms tracing and resumes a suspended child. report_to_afl must be true for
 * exactly one call per outer request: AFL++ reads one pid, then one status. */
static int start_and_resume(s32 child_pid, int report_to_afl)
{
  start_trace(child_pid, false);

  if (report_to_afl) {
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) return -1;
  }

  if (kill(child_pid, SIGCONT) < 0) return -1;

  return 0;
}

/* Waits for the child to exit or hit the drain safety net, then finalizes the
 * trace. Shared by the normal path, hidden retries, and calibration steps. */
static int wait_for_child_and_stop_trace(s32 *out_status)
{
  s32 status;

  while (1) {
    if (read(proxy_st_fd, &status, 4) != 4) return -1;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
      trace_suspend_resume_callback();
    } else {
      trace_child_exited_callback();
      break;
    }
  }

  if (stop_trace(false) < 0) return -1;
  if (out_status) *out_status = status;

  return 0;
}

#ifdef AFLCS_STALKER_DECODER
struct calib_ctx {
  s32 child_pid;
  int have_child;
};

/* freq_gov_calibrate()'s run_one_shot callback: one exec of the staged input,
 * reporting whether it overflowed. Never reports to AFL++. */
static int calibration_run_one_shot(void *ctx_)
{
  struct calib_ctx *ctx = (struct calib_ctx *)ctx_;
  s32 pid;

  if (ctx->have_child) {
    pid = ctx->child_pid;
    ctx->have_child = 0;
  } else {
    pid = fork_fresh_child();
    if (pid < 0) return 1;
  }
  ctx->child_pid = pid;

  if (start_and_resume(pid, /*report_to_afl=*/0) < 0) return 1;
  if (wait_for_child_and_stop_trace(NULL) < 0) return 1;
  freq_gov_restore_max();

  return decoding_on && trace_did_overflow();
}

/* Fork+arm+resume a hidden retry child at the governor's frequency for
 * `mode`. Never reports to AFL++. */
static s32 retry_child(freq_mode_t mode)
{
  s32 pid = fork_fresh_child();
  if (pid < 0) return -1;

  freq_gov_apply(mode);
  if (start_and_resume(pid, /*report_to_afl=*/0) < 0) return -1;

  return pid;
}
#endif /* AFLCS_STALKER_DECODER */

static u32 __afl_next_testcase(void)
{
  s32 was_killed, child_pid;
#ifdef AFLCS_STALKER_DECODER
  freq_mode_t mode;
#endif

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &was_killed, 4) != 4) return 1;
  if (write(proxy_ctl_fd, &was_killed, 4) != 4) return -1;

  /* Wait for child by reading from the pipe. Abort if read fails. */
  if (read(proxy_st_fd, &child_pid, 4) != 4) return -1;

  if (unlikely(first_run)) {
    if (init_trace(fsrv_pid, child_pid) < 0) return -1;
    first_run = 0;

#ifdef AFLCS_STALKER_DECODER
    freq_gov_init(trace_cpu, cov_type == edge_cov);
#endif
  }

#ifdef AFLCS_STALKER_DECODER
  mode = current_freq_mode();

  if (unlikely(needs_calibration)) {
    needs_calibration = 0;

    /* Calibrate on this first input: ramp up from the floor with a fresh
     * child per step, stopping at the first overflow. */
    struct calib_ctx ctx = { .child_pid = child_pid, .have_child = 1 };
    freq_gov_calibrate(mode, calibration_run_one_shot, &ctx);

    if (cov_type == edge_cov) {
      struct calib_ctx bb_ctx = { .child_pid = -1, .have_child = 0 };

      if (trace_set_bb_mode(1) < 0) {
        FATAL("Failed to enable ETM branch broadcast for AFLCS_COV=edge");
      }

      /* Re-ramp with branch broadcast on */
      freq_gov_calibrate(mode, calibration_run_one_shot, &bb_ctx);
    }

    child_pid = fork_fresh_child();
    if (child_pid < 0) return -1;
  }

  freq_gov_apply(mode);
#endif /* AFLCS_STALKER_DECODER */

  if (start_and_resume(child_pid, /*report_to_afl=*/1) < 0) return -1;

  return child_pid;
}

static s32 __afl_end_testcase(s32 status)
{
  if (write(FORKSRV_FD + 1, &status, 4) != 4) return -1;

  return 0;
}

void save_trace_on_abort_handler(int sig){
  signal(SIGABRT, SIG_DFL);
  export_trace("cstrace.bin", "decoderargs.txt");
  abort();
}

/* you just need to modify the while() loop in this main() */

int main(int argc, char *argv[])
{
  s32 status;
  int i;
  char **argvp;
  char *ptr;

  if(signal(SIGABRT, save_trace_on_abort_handler) == SIG_ERR) {
    perror("Failed to set signal handler");
    return 1;
  }

  ld_forksrv_path = get_libforksrv_path("libforksrv.so");
  if(access(ld_forksrv_path, F_OK) != 0){
    fprintf(stderr, "Error: libforksrv.so not found\n");
    return -1;
  }

  if (geteuid() != 0) {
    fprintf(stderr, "Error: root are required\n");
    return -1;
  }
  if (argc < 3) {
    fprintf(stderr, "Error with argv\n");
    return -1;
  }
  if(check_udmabuf() != 0){
    fprintf(stderr, "Error: u-dma-buf kernel module are required\n");
    return -1;
  }

  argvp = NULL;
  registration_verbose = getenv("AFLCS_REG_VERBOSE") ? atoi(getenv("AFLCS_REG_VERBOSE")) : 0;

#ifdef AFLCS_STALKER_DECODER
  if ((ptr = getenv("AFLCS_FREQ_CALIBRATE")) != NULL && !strcmp(ptr, "0")) {
    needs_calibration = 0;
    OKF("afl-cs-proxy upfront frequency calibration OFF");
  }
#endif

  if (getenv("AFLCS_NO_DECODER")) {
    OKF("afl-cs-proxy decoder OFF");
    decoding_on = false;
  }else {
    OKF("afl-cs-proxy decoder ON");
    decoding_on = true;
  }

  /* here you specify the map size you need that you are reporting to
     afl-fuzz.  Any value is fine as long as it can be divided by 32. */
  trace_bitmap_size = MAP_SIZE;  // default is 65536
  __afl_proxy_name = argv[0];

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--") && i + 1 < argc) {
      argvp = &argv[++i];
      if (access(argvp[0], F_OK) != 0) {
        FATAL("The target executable file '%s' was not found\n", argvp[0]);
      }
      break;
    } else if (argc > 2 && i + 1 >= argc) {
      FATAL("Invalid option '%s'", argv[i]);
    }
  }

  /* Mark as AFL++ CoreSight mode is enabled. */
  setenv("__AFLCS_ENABLE", "1", 0);

  if ((ptr = getenv("AFLCS_COV")) != NULL) {
    if (!strcmp(ptr, "edge")) {
      cov_type = edge_cov;
    } else if (!strcmp(ptr, "path")) {
      cov_type = path_cov;
    } else {
      FATAL("Error: unknown coverage type '%s'", ptr);
    }
  }

  if ((ptr = getenv("AFLCS_UDMABUF")) != NULL) {
    udmabuf_num = atoi(ptr);
  }

  /* then we initialize the shared memory map and start the forkserver */
  __afl_map_shm();
  __afl_start_forkserver(argvp);

  while (__afl_next_testcase() > 0) {
#ifdef AFLCS_STALKER_DECODER
    /* Stalker's ACFMM: only its decoder reports per-exec overflow, so under
     * coresight-decoder this loop is a plain single-pass wait-and-finalize. */
    freq_mode_t mode = current_freq_mode();
    int cur_repetition_num = 0;
    int forced_min_done = 0;
    int overflowed;

    for (;;) {
      /* Handle child suspend/resume, then finalize this attempt's trace. */
      if (wait_for_child_and_stop_trace(&status) < 0) return -1;
      freq_gov_restore_max();

      overflowed = decoding_on && trace_did_overflow();
      total_exec_count++;
      if (overflowed) overflow_exec_count++;
      if (decoding_on && (total_exec_count % 100) == 0 &&
          getenv("AFLCS_STALKER_DIAG")) {
        fprintf(stderr, "[OVERFLOW] %llu/%llu execs overflowed (%.2f%%)\n",
                (unsigned long long)overflow_exec_count,
                (unsigned long long)total_exec_count,
                100.0 * (double)overflow_exec_count / (double)total_exec_count);
      }

      int should_retry = freq_gov_should_retry(mode, overflowed, cur_repetition_num);
      freq_gov_on_result(mode, overflowed);

      if (should_retry) {
        /* Overflow on the precise pass: throttle down and re-execute via the
         * inner protocol. Matches Stalker's bb_mode-gated retry_to_fuzz(). */
        cur_repetition_num++;
        if (retry_child(mode) < 0) return -1;
        continue;
      }

      /* Check for overflow and reduce freq if needed */
      if (overflowed && mode == FREQ_MODE_ADDR && !forced_min_done &&
          !freq_gov_at_floor(mode) &&
          cur_repetition_num >= FREQ_GOV_MAX_REPETITION_NUM) {
        /* Retries exhausted: one final run pinned to the floor frequency. */
        forced_min_done = 1;
        freq_gov_force_min();
        if (retry_child(mode) < 0) return -1;
        continue;
      }

      break;
    }
#else
    if (wait_for_child_and_stop_trace(&status) < 0) return -1;
#endif

    if(!decoding_on){
      trace_bitmap[0] = 1;
    }
    /* report the test case is done and wait for the next */
    if (__afl_end_testcase(status) < 0) return -1;

#ifdef EXEC_COUNT
    if (++exec_count > EXEC_COUNT) return 0;
#endif
  }

  return 0;
}
