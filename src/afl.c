
#include "afl/common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "proc-trace.h"
#include "afl.h"

#define AFL_EXEC_TRIAL_MAX 16

#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)

static unsigned char dummy[MAP_SIZE];
unsigned char *afl_area_ptr = dummy;

static int forkserver_installed = 0;

unsigned char afl_fork_child;
unsigned int afl_forksrv_pid;
unsigned char is_persistent;

unsigned int afl_inst_rms = MAP_SIZE;

char *dec_path;
unsigned int afl_map_size = MAP_SIZE;

extern char **dec_args;
extern bool needs_rerun;

void afl_setup(void)
{
  char *id_str;
  char *inst_r;
  int shm_id;

  /* XXX: proc-trace uses its own CPU affinity settings */
  if (!getenv("AFL_NO_AFFINITY")) {
    fprintf(stderr, "[AFL] ERROR: AFL_NO_AFFINITY must be set to use CoreSight mode\n");
    exit(1);
  }

  /* XXX: Max CPU freq causes ETM buffer overflows on ThunderX2 */
  if (!getenv("AFL_SKIP_CPUFREQ")) {
    fprintf(stderr, "[AFL] ERROR: AFL_SKIP_CPUFREQ must be set to use CoreSight mode\n");
    exit(1);
  }

  inst_r = getenv("AFL_INST_RATIO");
  if (inst_r) {
    unsigned int r;

    r = atoi(inst_r);

    if (r  > 100) {
      r = 100;
    }
    if (!r) {
      r = 1;
    }

    afl_inst_rms = MAP_SIZE * r / 100;
  }
  
  id_str = getenv(SHM_ENV_VAR);
  if (id_str) {
    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void *)-1) {
      exit(1);
    }

    /* With AFL_INST_RATIO set to low value, we want to touch the bitmap
     * so that the parent doesn't give up on us. */
    if (inst_r) {
      afl_area_ptr[0] = 1;
    }
  }

  /* TODO: Support persistent mode */
}

void afl_forkserver(char *argv[])
{
  unsigned char tmp[4] = {0};
  int first_run;
  int proxy_st_pipe[2];
  int proxy_ctl_pipe[2];
  int proxy_st_fd;
  int proxy_ctl_fd;
  pid_t child_pid;
  u8 child_stopped = 0;
  u32 was_killed;
  int status;
  int trial;

  if (forkserver_installed == 1) {
    return;
  }
  forkserver_installed = 1;

  if (pipe(proxy_st_pipe) || pipe(proxy_ctl_pipe)) {
    fprintf(stderr, "[AFL] ERROR: pipe() failed\n");
    exit(1);
  }

  afl_forksrv_pid = fork();
  if (afl_forksrv_pid < 0) {
    fprintf(stderr, "[AFL] ERROR: fork() failed\n");
    exit(2);
  }

  if (!afl_forksrv_pid) {
    /* Child process. Close descriptors and run free. */
    if (dup2(proxy_ctl_pipe[0], AFLCS_FORKSRV_FD) < 0) {
      fprintf(stderr, "[AFL] ERROR: dup2() failed\n");
      exit(3);
    }
    if (dup2(proxy_st_pipe[1], AFLCS_FORKSRV_FD + 1) < 0) {
      fprintf(stderr, "[AFL] ERROR: dup2() failed\n");
      exit(4);
    }
    afl_fork_child = 1;
    close(proxy_ctl_pipe[0]);
    close(proxy_ctl_pipe[1]);
    close(proxy_st_pipe[0]);
    close(proxy_st_pipe[1]);
    close(FORKSRV_FD);
    close(FORKSRV_FD + 1);

    execvp(argv[0], argv);

    return;
  }

  /* Parent. */
  close(proxy_ctl_pipe[0]);
  close(proxy_st_pipe[1]);
  proxy_ctl_fd = proxy_ctl_pipe[1];
  proxy_st_fd = proxy_st_pipe[0];

  if (read(proxy_st_fd, tmp, 4) != 4) {
    exit(5);
  }

  memcpy(&status, tmp, 4);
  if (getenv("AFL_DEBUG")) {
    fprintf(stderr, "Debug: Sending status %08x\n", status);
  }

  /* Tell the parent that we're alive. If the parent doesn't want
   * to talk, assume that we're not running in forkserver mode. */
  if (write(FORKSRV_FD + 1, tmp, 4) != 4) {
    exit(6);
  }

  first_run = 1;

  /* All right, let's await orders... */
  while (1) {
    /* Whoops, parent dead? */
    if (read(FORKSRV_FD, &was_killed, 4) != 4) {
      exit(2);
    }

    if (write(proxy_ctl_fd, &was_killed, 4) != 4) {
      exit(3);
    }

    /* If we stopped the child in persistent mode, but there was a race
     * condition and afl-fuzz already issued SIGKILL, wriite off the old
     * process. */
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) {
        exit(8);
      }
    }

    if (!child_stopped) {
      /* Wait for target by reading from the pipe. */
      if (read(proxy_st_fd, &child_pid, 4) != 4) {
        exit(4);
      }
    } else {
      /* Special handling for persistent mode: if the child is alive but
       * currently stopped, simple restart it with SIGCONT. */
      kill(child_pid, SIGCONT);
      child_stopped = 0;
    }

    afl_start_trace(child_pid);

    /* Resume child process. */
    kill(child_pid, SIGCONT);

    /* Parent. */
    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      exit(5);
    }

    if (read(proxy_st_fd, &status, 4) != 4) {
      exit(6);
    }

    afl_stop_trace();

    if (needs_rerun) {
      fprintf(stderr, "[AFL] ERROR: failed to retrieve bitmap. trial: %d\n", trial);
      needs_rerun = false;
      status = -1;
      exit(5);
    }

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
     * a successfull run. In this case, we want to wake it up without forking
     * again. */
    if (WIFSTOPPED(status)) {
      child_stopped = 1;
    } else if (first_run && is_persistent) {
      fprintf(stderr, "[AFL] ERROR: no persistent iteration executed\n");
      exit(12);
    }

    first_run = 0;

    if (write(FORKSRV_FD + 1, &status, 4) != 4) {
      exit(7);
    }
  }
}
