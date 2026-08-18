/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Ricerca Security, Inc. All rights reserved. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "csaccess.h"
#include "csregistration.h"
#include "csregisters.h"
#include "cs_util_create_snapshot.h"

#include "libcsdec.h"
#ifdef AFLCS_STALKER_DECODER
#include "stalker.h"
#endif

#include "common.h"
#include "known-boards.h"
#include "config.h"
#include "utils.h"

#define DEFAULT_TRACE_CPU 0
#define DEFAULT_DECODER_CPU 1
#define DEFAULT_UDMABUF_NUM 0
#define DEFAULT_ETF_SIZE 0x1000
#define DEFAULT_TRACE_SIZE 0x800000
#define DEFAULT_TRACE_NAME "cstrace.bin"
#define DEFAULT_TRACE_ARGS_NAME "decoderargs.txt"

#define TRACE_DISABLE_TRIAL 8
#define TRACE_DISABLE_TRIAL_USLEEP 10

#define CSDBG()                                     \
  do {                                              \
    fprintf(stderr, "%s:%d\n", __func__, __LINE__); \
  } while (0);

typedef enum {
  init_state,
  fini_state,
  ready_state,
  running_state,
  suspended_state,
} trace_state_t;

typedef enum {
  init_event,
  fini_event,
  ready_event,
  start_event,
  stop_event,
  suspend_event,
  resume_event,
} trace_event_t;

char *board_name = DEFAULT_BOARD_NAME;
const struct board *board;
struct cs_devices_t devices;
int udmabuf_num = DEFAULT_UDMABUF_NUM;
bool decoding_on = false;
int trace_cpu = -1;
bool export_config = false;
bool coverage = false;
unsigned long etr_ram_addr = 0;
size_t etr_ram_size = 0;
int range_count = 0;
struct map_info map_info[RANGE_MAX];
struct libcsdec_memory_map *mem_map = NULL;
struct libcsdec_memory_image *mem_img = NULL;
cov_type_t cov_type = edge_cov;

unsigned char *trace_bitmap = NULL;
unsigned int trace_bitmap_size = 0;

/* Set when a decode pass reaches a LIBCSDEC_ERROR_OVERFLOW_PACKET */
static bool trace_overflow_occurred = false;

static int trace_id = -1;
static pid_t child_pid = -1;
static bool is_first_trace = true;
static libcsdec_t decoder = NULL;
static void *trace_buf = NULL;
static size_t trace_buf_size = 0;
static void *trace_buf_ptr = NULL;
static void *decoded_trace_buf = NULL;

/* Diagnostic: bytes actually captured into trace_buf so far this exec */
size_t trace_captured_bytes(void)
{
  return (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
}

static pthread_t decoder_thread;

static pthread_mutex_t trace_mutex;
static pthread_mutex_t trace_state_mutex;
static trace_state_t trace_state = init_state;
static trace_event_t trace_event = init_event;

static pthread_mutex_t ev_mutex;
static pthread_cond_t  ev_cond;
static bool start_pending   = false;
static bool suspend_pending = false;
static bool stop_pending    = false;
static bool fini_pending    = false;   /* sticky */

static pthread_mutex_t trace_decoder_mutex;
static pthread_cond_t trace_decoder_cond;
static bool decoder_ready = true;

extern int registration_verbose;

static int enable_cs_trace(pid_t pid);
static int disable_cs_trace(bool disable_all);


static void signal_event(bool *flag)
{
  pthread_mutex_lock(&ev_mutex);
  *flag = true;
  pthread_cond_broadcast(&ev_cond);
  pthread_mutex_unlock(&ev_mutex);
}

/* wait until *flag (consume it) or fini (leave sticky). returns true if fini. */
static bool wait_event(bool *flag)
{
  bool is_fini;
  pthread_mutex_lock(&ev_mutex);
  while (!*flag && !fini_pending)
    pthread_cond_wait(&ev_cond, &ev_mutex);
  is_fini = fini_pending && !*flag;
  if (!is_fini) *flag = false;
  pthread_mutex_unlock(&ev_mutex);
  return is_fini;
}

static void set_trace_state(trace_state_t new_state)
{
  pthread_mutex_lock(&trace_state_mutex);
  trace_state = new_state;
  pthread_mutex_unlock(&trace_state_mutex);
}

static int trace_sink_polling(unsigned long decoding_threshold)
{
  int ret;
  unsigned long init_pos;
  unsigned long curr_offset;

  pthread_mutex_lock(&trace_decoder_mutex);
  decoder_ready = false;
  pthread_cond_broadcast(&trace_decoder_cond);
  pthread_mutex_unlock(&trace_decoder_mutex);

  ret = 0;
  init_pos = cs_get_buffer_rwp(devices.etb);

  while (!kill(child_pid, 0)) {
    curr_offset = cs_get_buffer_rwp(devices.etb) - init_pos;
    if (curr_offset > decoding_threshold) {
      /* Suspend child_pid process. */
      ret = kill(child_pid, SIGSTOP);
      if (ret < 0) {
        if (errno == ESRCH) {
          /* child_pid killed. */
          goto killed;
        }
        perror("kill");
        goto exit;
      }

      /* Wait for suspending trace. */
      wait_event(&suspend_pending);

      if ((ret = disable_cs_trace(false)) < 0) {
        fprintf(stderr, "disable_cs_trace() failed\n");
        goto exit;
      }
      fetch_trace();
      /* fetch_trace() empties the ETR via cs_empty_trace_buffer(), which
       * resets the hardware write pointer back to the buffer base */
      init_pos = cs_get_buffer_rwp(devices.etb);

      enable_cs_trace(child_pid);
      /* Continue child_pid process. */
      ret = kill(child_pid, SIGCONT);
      if (ret < 0) {
        if (errno == ESRCH) {
          /* child_pid killed. */
          goto killed;
        }
        perror("kill");
        goto exit;
      }

      /* Decode trace during the process is running. */
      if ((ret = decode_trace()) < 0) {
        fprintf(stderr, "decode_trace() failed\n");
        goto exit;
      }
    }
  }

killed:
  wait_event(&stop_pending);
  fetch_trace();
  if ((ret = decode_trace()) < 0) {
    fprintf(stderr, "decode_trace() failed\n");
    goto exit;
  }

exit:
  pthread_mutex_lock(&trace_decoder_mutex);
  decoder_ready = true;
  pthread_cond_broadcast(&trace_decoder_cond);
  pthread_mutex_unlock(&trace_decoder_mutex);

  return ret;
}

static void *decoder_worker(void *arg)
{
  trace_event_t event;
#ifndef AFLCS_STALKER_DECODER
  size_t etf_ram_size;
#endif
  unsigned long decoding_threshold;

  if (etr_ram_size == 0) {
    etr_ram_size = cs_get_buffer_size_bytes(devices.etb);
  }

#ifdef AFLCS_STALKER_DECODER
  /* Stalker lets the child run completely */
  decoding_threshold = etr_ram_size / 2;
#else
  /* Base coresight mode: drain against whichever sink is actually the
   * bottleneck. */
  if (devices.trace_sinks[0]) {
    etf_ram_size = (size_t)cs_get_buffer_size_bytes(devices.trace_sinks[0]);
    if (etf_ram_size < etr_ram_size) {
      decoding_threshold = etf_ram_size * 2;
    } else {
      decoding_threshold = etr_ram_size;
    }
  } else {
    decoding_threshold = etr_ram_size;
  }
#endif

  while (1) {
      if (wait_event(&start_pending)) break;
      trace_sink_polling(decoding_threshold);
  }

  return NULL;
}

/* TODO: Take cov_type as a argument. */
static int reset_decoder(struct map_info *map_info, int map_info_num)
{
  if (!decoder) {
    return -1;
  }

#ifdef AFLCS_STALKER_DECODER
  trace_overflow_occurred = false;
  return stalker_reset();
#else
  libcsdec_result_t ret;
  int i;

  if (!mem_map) {
    mem_map = malloc(sizeof(struct libcsdec_memory_map) * map_info_num);
    if (!mem_map) {
      perror("malloc");
      return -1;
    }
    for (i = 0; i < map_info_num; i++) {
      mem_map[i].start = map_info[i].start;
      mem_map[i].end = map_info[i].end;
      strncpy(mem_map[i].path, map_info[i].path, sizeof(map_info[i].path) - 1);
    }
  }

  ret = LIBCSDEC_ERROR;

  trace_overflow_occurred = false;

  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_reset_edge(decoder, trace_id, map_info_num, mem_map);
      break;
    case path_cov:
      ret = libcsdec_reset_path(decoder, trace_id, map_info_num, mem_map);
      break;
    default:
      return -1;
  }

  return (ret == LIBCSDEC_SUCCESS) ? 0 : -1;
#endif
}

/* TODO: Take cov_type as a argument. */
static int run_decoder(void *buf, size_t buf_size)
{
  if (!decoder) {
    return -1;
  }

#ifdef AFLCS_STALKER_DECODER
  {
    bool overflow = false;
    int ret;
    ret = stalker_run(trace_bitmap, trace_bitmap_size, buf, buf_size, &overflow);
    if (overflow) {
      trace_overflow_occurred = true;
    }
    return ret;
  }
#else
  libcsdec_result_t ret = LIBCSDEC_ERROR;

  switch (cov_type) {
    case edge_cov:
      ret = libcsdec_run_edge(decoder, buf, buf_size);
      break;
    case path_cov:
      ret = libcsdec_run_path(decoder, buf, buf_size);
      break;
    default:
      return -1;
  }

  if (ret == LIBCSDEC_ERROR_OVERFLOW_PACKET) {
    trace_overflow_occurred = true;
    fprintf(stderr, "[DECODER] overflow packet observed, truncating decode for this exec\n");
  }

  return (ret == LIBCSDEC_SUCCESS) ? 0 : -1;
#endif
}

/* Checks if any decode pass overflowed */
bool trace_did_overflow(void)
{
  return trace_overflow_occurred;
}

static libcsdec_t init_decoder(struct map_info *map_info, int map_info_num)
{
  libcsdec_t decoder;

  if (!trace_bitmap) {
    trace_bitmap = malloc(trace_bitmap_size);
    if (!trace_bitmap) {
      perror("malloc");
      decoder = (libcsdec_t)NULL;
      goto exit;
    }
  }

#ifdef AFLCS_STALKER_DECODER
  /* Actual decode state lives in stalker-decoder/'s globals, set up once
   * by stalker_setup() (called from init_trace(), which has the pid this
   * needs). */
  decoder = (libcsdec_t)STALKER_DECODER_HANDLE;
  goto exit;
#else
  int i;

  if (!mem_img) {
    mem_img = malloc(sizeof(struct libcsdec_memory_image) * map_info_num);
    if (!mem_img) {
      perror("malloc");
      decoder = (libcsdec_t)NULL;
      goto exit;
    }
    for (i = 0; i < map_info_num; i++) {
      mem_img[i].data = map_info[i].buf;

      char tmp[PATH_MAX];
      strncpy(tmp, map_info[i].path, sizeof(tmp) - 1);
      tmp[sizeof(tmp) - 1] = '\0';
      const char *bname = basename(tmp);
      snprintf(mem_img[i].path, sizeof(mem_img[i].path), "%s", bname);

      mem_img[i].size =
          (size_t)ALIGN_UP(map_info[i].end - map_info[i].start, PAGE_SIZE);
    }
  }
  if (coverage) {
    if (setenv("INSN_SAVE", "1", 1) != 0) {
      perror("setenv");
    }
  }
  switch (cov_type) {
    case edge_cov:
      decoder = libcsdec_init_edge(trace_bitmap, trace_bitmap_size,
                                   map_info_num, mem_img);
      break;
    case path_cov:
      decoder = libcsdec_init_path(trace_bitmap, trace_bitmap_size,
                                   map_info_num, mem_img);
      break;
    default:
      decoder = (libcsdec_t)NULL;
      break;
  }
#endif

exit:
  return decoder;
}

/* TODO: Take cov_type as a argument. */
static int fini_decoder(void)
{
  if (!decoder) {
    return -1;
  }

#ifdef AFLCS_STALKER_DECODER
  return stalker_fini();
#else
  switch (cov_type) {
    case edge_cov:
      libcsdec_finish_edge(decoder);
      break;
    case path_cov:
      libcsdec_finish_path(decoder);
      break;
  }

  return 0;
#endif
}

/* FIXME: Do not initialize global variables in the function */
static int alloc_trace_buf(void)
{
  // Free previous mapping
  if (trace_buf) {
    munmap(trace_buf, trace_buf_size);
    trace_buf = NULL;
    trace_buf_size = 0;
  }

  trace_buf = mmap(NULL, DEFAULT_TRACE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (trace_buf == MAP_FAILED) {
    perror("mmap");
    trace_buf = NULL;
    return -1;
  }
  trace_buf_size = DEFAULT_TRACE_SIZE;
  trace_buf_ptr = trace_buf;
  decoded_trace_buf = trace_buf;  // both reset to same base
  return 0;
}

/* FIXME: Make it better */
static void free_trace_buf(void)
{
  if (devices.etb) {
    cs_empty_trace_buffer(devices.etb);
  }

  if (trace_buf) {
    munmap(trace_buf, trace_buf_size);
    trace_buf_ptr = NULL;
    decoded_trace_buf = NULL;
  }
}

int export_trace(const char *trace_name, const char *trace_args_name)
{
  int ret;
  char *cwd;
  char trace_path[PATH_MAX];
  char decoder_args_path[PATH_MAX];
  FILE *fp;

  ret = -1;
  fprintf(stderr, "Exporting a trace to %s and %s\n", trace_name, trace_args_name);
  cwd = getcwd(NULL, 0);
  if (!cwd) {
    perror("getcwd");
    goto exit;
  }

  memset(trace_path, 0, sizeof(trace_path));
  memset(decoder_args_path, 0, sizeof(decoder_args_path));
  snprintf(trace_path, sizeof(trace_path), "%s/%s", cwd, trace_name);
  snprintf(decoder_args_path, sizeof(decoder_args_path), "%s/%s", cwd,
           trace_args_name);

  if (export_decoder_args(trace_id, trace_path, decoder_args_path, map_info,
                          range_count) < 0) {
    goto exit;
  }

  fp = fopen(trace_path, "wb");
  if (!fp) {
    perror("fopen");
    goto exit;
  }

  fwrite(trace_buf, (size_t)((char *)trace_buf_ptr - (char *)trace_buf), 1, fp);
  fclose(fp);

  ret = 0;

exit:
  if (cwd) {
    free(cwd);
  }

  return ret;
}

static int enable_cs_trace(pid_t pid)
{
  int ret;

  ret = -1;

  pthread_mutex_lock(&trace_mutex);

  if (is_first_trace) {
    /* Do not specify traced PID in forkserver mode */
    if (configure_trace(board, &devices, map_info, range_count, pid) < 0) {
      fprintf(stderr, "configure_trace() failed\n");
      goto exit;
    }
    /* Enable ETMs and trace sinks for the first time */
    if (enable_trace(board, &devices) < 0) {
      fprintf(stderr, "enable_trace() failed\n");
      goto exit;
    }
    is_first_trace = false;
  } else {
    /* Enable trace sinks only once ETMs enabled */
    if (enable_trace_sinks_only(board, &devices) < 0) {
      fprintf(stderr, "enable_trace_sinks_only() failed\n");
      goto exit;
    }
  }

  if (export_config) {
    do_dump_config(board, &devices, 0);
  }

  ret = 0;

exit:
  if (ret < 0) {
    cs_shutdown();
  }
  pthread_mutex_unlock(&trace_mutex);

  return ret;
}

static int disable_cs_trace(bool disable_all)
{
  int ret;
  int disable_trial;

  pthread_mutex_lock(&trace_mutex);

  disable_trial = 0;
  while (disable_trial++ < TRACE_DISABLE_TRIAL) {
    if (disable_all) {
      if ((ret = disable_trace(board, &devices)) < 0) {
        fprintf(stderr, "disable_trace() failed\n");
      }
    } else {
      if ((ret = disable_trace_sinks_only(board, &devices)) < 0) {
        fprintf(stderr, "disable_trace_sinks_only() failed\n");
      }
    }
    if (!(ret < 0)) {
      break;
    }
    usleep(TRACE_DISABLE_TRIAL_USLEEP);
    cs_reset_error_count();
  }

  pthread_mutex_unlock(&trace_mutex);

  return ret;
}


static void debug_etr_state(struct cs_devices_t *devices) {
    int unread = cs_get_buffer_unread_bytes(devices->etb);
    unsigned long rwp = cs_get_buffer_rwp(devices->etb);
    fprintf(stderr, "[DBG] ETR unread bytes: %d\n", unread);
    fprintf(stderr, "[DBG] ETR RWP: 0x%lx\n", rwp);

    // Read ETR status register directly
    unsigned int sts = cs_device_read(devices->etb, CS_ETB_STATUS);
    unsigned int ffcr = cs_device_read(devices->etb, CS_ETB_FLFMT_CTRL);
    unsigned int mode = cs_device_read(devices->etb, CS_TMC_MODE);
    unsigned int size = cs_device_read(devices->etb, CS_ETB_RAM_DEPTH);
    unsigned int dbalo = cs_device_read(devices->etb, CS_TMC_DBALO);
    unsigned int dbahi = cs_device_read(devices->etb, CS_TMC_DBAHI);
    unsigned int axictl = cs_device_read(devices->etb, CS_ETB_AXICTL);

    fprintf(stderr, "[DBG] ETR STS:    0x%08x\n", sts);
    fprintf(stderr, "[DBG] ETR FFCR:   0x%08x\n", ffcr);
    fprintf(stderr, "[DBG] ETR MODE:   0x%08x\n", mode);
    fprintf(stderr, "[DBG] ETR SIZE:   0x%08x (= %u bytes)\n", size, size * 4);
    fprintf(stderr, "[DBG] ETR DBALO:  0x%08x\n", dbalo);
    fprintf(stderr, "[DBG] ETR DBAHI:  0x%08x\n", dbahi);
    fprintf(stderr, "[DBG] ETR AXICTL: 0x%08x\n", axictl);

    // Check ETF states too
    for (int i = 0; i < devices->num_trace_sinks; i++) {
        fprintf(stderr, "[DBG] === ETF%d ===\n", i);
        dump_tmc_config(devices->trace_sinks[i]);
    }
}

int fetch_trace(void)
{
  int ret;
  cs_device_t etb;
  int len;
  size_t buf_remain, buf_used;
  void *new_trace_buf;
  size_t new_trace_buf_size;
  int n;

  ret = -1;

  pthread_mutex_lock(&trace_mutex);

  etb = devices.etb;
  len = cs_get_buffer_unread_bytes(etb);

  trace_buf_ptr = (void *)ALIGN_UP((unsigned long)trace_buf_ptr, 0x8);

  buf_remain =
      trace_buf_size - (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  /* No space left in trace_buf. */
  if ((size_t)len > buf_remain) {
    new_trace_buf_size = trace_buf_size * 2;
    new_trace_buf = mremap(trace_buf, trace_buf_size, new_trace_buf_size, 0);

    if (!new_trace_buf) {
      perror("mremap");
      goto exit;
    }
    decoded_trace_buf =
        (void *)((char *)new_trace_buf +
                 ((char *)decoded_trace_buf - (char *)trace_buf));
    trace_buf_ptr = (void *)((char *)new_trace_buf +
                             ((char *)trace_buf_ptr - (char *)trace_buf));
    trace_buf = new_trace_buf;
    trace_buf_size = new_trace_buf_size;
    buf_remain = (size_t)((char *)trace_buf_ptr - (char *)trace_buf);
  }

  n = cs_get_trace_data(etb, trace_buf_ptr, buf_remain);
  if (n <= 0) {
    fprintf(stderr, "[FETCH] ERROR: failed to get trace (n=%d)\n", n);
  } else if (n < len) {
    fprintf(stderr, "[FETCH] WARNING: incomplete trace (got %d of %d bytes)\n", n, len);
  }
  cs_empty_trace_buffer(etb);
  trace_buf_ptr = (void *)((char *)trace_buf_ptr + n);

  ret = 0;

exit:
  pthread_mutex_unlock(&trace_mutex);
  return ret;
}

int decode_trace(void)
{
  int ret;
  void *buf;
  size_t buf_size;

  buf = decoded_trace_buf;
  buf_size = (size_t)((char *)trace_buf_ptr - (char *)buf);

  ret = run_decoder(buf, buf_size);
  if (ret < 0) {
    goto exit;
  }

  decoded_trace_buf = (void *)((char *)buf + buf_size);

exit:

  return ret;
}

void trace_suspend_resume_callback(void) {
  set_trace_state(suspended_state);
  signal_event(&suspend_pending);
}

/* Call when the proxy observes the traced child has actually exited/died,
 * as opposed to the SIGSTOP the decoder thread expects when it pauses the
 * child mid-execution to drain the ETR buffer (trace_sink_polling()'s
 * kill(child_pid, SIGSTOP) + wait_event(&suspend_pending)) */
void trace_child_exited_callback(void) {
  signal_event(&suspend_pending);
}

/* Start trace session. CoreSight and decoder must be initialized. */
int start_trace(pid_t pid, bool use_pid_trace)
{
  int ret;

  if ((ret = set_cpu_affinity(trace_cpu, pid)) < 0) {
    fprintf(stderr, "set_cpu_affinity() failed\n");
    goto exit;
  }

  alloc_trace_buf();

  if (decoding_on && ((ret = reset_decoder(map_info, range_count)) < 0)) {
    fprintf(stderr, "reset_decoder() failed\n");
    goto exit;
  }

  child_pid = pid;
  if ((ret = enable_cs_trace(use_pid_trace ? pid : 0)) < 0) {
    fprintf(stderr, "enable_cs_trace() failed\n");
  }

  if (ret < 0) {
    goto exit;
  }

  set_trace_state(running_state);
  signal_event(&start_pending);

exit:
  return ret;
}

/* Stop trace session. CoreSight and decoder are still available. */
int stop_trace(bool disable_all)
{
  int ret;

  if ((ret = disable_cs_trace(disable_all)) < 0) {
    fprintf(stderr, "disable_cs_trace() failed\n");
    goto exit;
  }

  set_trace_state(ready_state);
  signal_event(&stop_pending);


  pthread_mutex_lock(&trace_decoder_mutex);
  while (!decoder_ready) {
    pthread_cond_wait(&trace_decoder_cond, &trace_decoder_mutex);
  }
  pthread_mutex_unlock(&trace_decoder_mutex);

exit:
  return ret;
}

/* Initialize trace. Called on the first time and only once. */
int init_trace(pid_t parent_pid, pid_t pid)
{
  int ret;
  int preferred_cpu;
  int decoder_cpu;

  ret = -1;

  pthread_mutex_init(&trace_mutex, NULL);
  pthread_mutex_init(&trace_state_mutex, NULL);

  pthread_mutex_init(&ev_mutex, NULL);
  pthread_cond_init(&ev_cond, NULL);

  pthread_mutex_init(&trace_decoder_mutex, NULL);
  pthread_cond_init(&trace_decoder_cond, NULL);

  if (trace_cpu < 0) {
    if ((preferred_cpu = get_preferred_cpu(parent_pid)) < 0) {
      fprintf(stderr, "INFO: Failed to get preferred CPU\n");
      /* Some boards is not supported by get_preferred_cpu() */
      if ((preferred_cpu = find_free_cpu() < 0)) {
        fprintf(stderr, "WARNING: Failed to find free CPU. Use #%d\n",
                DEFAULT_TRACE_CPU);
      }
    }
    trace_cpu = preferred_cpu >= 0 ? preferred_cpu : DEFAULT_TRACE_CPU;
  }

  if (get_udmabuf_info(udmabuf_num, &etr_ram_addr, &etr_ram_size) < 0) {
    fprintf(stderr, "Failed to get u-dma-buf info\n");
    goto exit;
  }

  if ((range_count = setup_map_info(pid, map_info, RANGE_MAX)) < 0) {
    fprintf(stderr, "setup_map_info() failed\n");
    goto exit;
  }

  if (setup_named_board(board_name, &board, &devices, known_boards) < 0) {
    fprintf(stderr, "setup_named_board() failed\n");
    goto exit;
  }

  if ((trace_id = get_trace_id(board_name, trace_cpu)) < 0) {
    goto exit;
  }

  if (decoding_on) {
    decoder = init_decoder(map_info, range_count);
    if (!decoder) {
      fprintf(stderr, "init_decoder() failed\n");
      goto exit;
    }
#ifdef AFLCS_STALKER_DECODER
    if (stalker_setup(pid, map_info, range_count) < 0) {
      fprintf(stderr, "stalker_setup() failed\n");
      goto exit;
    }
#endif
    /* decoder_ready defaults to true so stop_trace() never blocks when no
     * decoder thread exists (AFLCS_NO_DECODER). Since we ARE spawning one
     * here, arm it false first otherwise stop_trace() for the very first
     * execution(s) sees the stale "ready" default and returns immediately. */
    decoder_ready = false;
    ret = pthread_create(&decoder_thread, NULL, decoder_worker, NULL);
    if (ret != 0) {
      fprintf(stderr, "pthread_create() failed: %d\n", ret);
      goto exit;
    }

    /* Using find_free_cpu() for decoder thread decreases performance on
     * Marvell ThunderX2. The tracee process and the decoder thread should be
     * in the same CPU core group. DEFAULT_DECODER_CPU fallback is 1.
     */
    if ((decoder_cpu = get_preferred_cpu(pid)) < 0 || decoder_cpu == trace_cpu) {
      decoder_cpu = DEFAULT_DECODER_CPU;
    }
    if (decoder_cpu >= 0) {
      if (set_pthread_cpu_affinity(decoder_cpu, decoder_thread) < 0) {
        fprintf(stderr, "set_pthread_cpu_affinity() failed");
      }
    }
  }

  set_trace_state(ready_state);
  ret = 0;

exit:
  if (ret != 0) {
    cs_shutdown();
  }

  return ret;
}

/* Finalize trace. Called after all trace sessions finished. */
void fini_trace(void)
{
  if (decoding_on) {
    /* Cancel decoder_thread. Assuming stop singal is sent prior to it. */
    set_trace_state(fini_state);
    signal_event(&fini_pending);
    pthread_join(decoder_thread, NULL);
  } else {
    fetch_trace();
  }

  export_trace(DEFAULT_TRACE_NAME, DEFAULT_TRACE_ARGS_NAME);

  if (registration_verbose > 0) {
    dump_map_info(stderr, map_info, range_count);
  }

  fini_decoder();

  free_trace_buf();

  cs_shutdown();

  pthread_cond_destroy(&trace_decoder_cond);
  pthread_mutex_destroy(&trace_decoder_mutex);

  pthread_mutex_destroy(&trace_mutex);
  pthread_mutex_destroy(&trace_state_mutex);

  pthread_cond_destroy(&ev_cond);
  pthread_mutex_destroy(&ev_mutex);
}
