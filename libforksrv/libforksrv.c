#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <signal.h>
#include <asm/unistd.h>
#include <sys/prctl.h>

#define FORKSRV_FD 198
#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)

void __cs_start_forkserver(void) {
    if(getenv("__CS_PROXY") != NULL) {
        /* CS-PROXY */
        fprintf(stdout, "Start forksrv\n");
    } else {
        /* CS-TRACE */
        if(getenv("__CS_TRACE") != NULL) {
            fprintf(stdout, "sigstop for cs-trace\n");
            raise(SIGSTOP);
            return;
        }else {
            fprintf(stdout, "Run without cs-proxy/cs-trace\n");
            return;
        }
    }
    int status;
    pid_t child_pid;

    static char tmp[4] = {0, 0, 0, 0};
    prctl(PR_SET_PDEATHSIG, SIGTERM);

    if (write(AFLCS_FORKSRV_FD + 1, tmp, 4) != 4) {
        _exit(-1);
    }

    while (1) {
        /* Whoops, parent dead? */
        if (read(AFLCS_FORKSRV_FD, tmp, 4) != 4) {
            _exit(1);
        }
        /* 10 retries checking for EAGAIN */
        {
            int attempt;
            for (attempt = 0; attempt < 10; attempt++) {
                child_pid = fork();
                if (child_pid >= 0 || errno != EAGAIN) {
                    break;
                }
                usleep(1000 << attempt);
            }
        }
        if (child_pid < 0) {
            _exit(4);
        }
        if (!child_pid) {
            prctl(PR_SET_PDEATHSIG, SIGCONT);
            /* Child process. Wait for parent start tracing */
            raise(SIGSTOP);
            /* Close descriptors and run free. */
            close(AFLCS_FORKSRV_FD);
            close(AFLCS_FORKSRV_FD + 1);

            return;
        }
        /* Parent. Wait for the child to actually reach its raise(SIGSTOP). */
        if (waitpid(child_pid, &status, WUNTRACED) < 0) {
            _exit(6);
        }
        if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)) {
            /* Relay early exit status to proxy. */
            if (write(AFLCS_FORKSRV_FD + 1, &status, 4) != 4) {
                _exit(7);
            }
            continue;
        }
        /* Child confirmed stopped. Now it's safe for the proxy to SIGCONT it. */
        if (write(AFLCS_FORKSRV_FD + 1, &child_pid, 4) != 4) {
            _exit(5);
        }
        while (1) {
            /* Get status. */
            if (waitpid(child_pid, &status, WUNTRACED) < 0) {
                _exit(8);
            }
            /* Relay status to proxy. */
            if (write(AFLCS_FORKSRV_FD + 1, &status, 4) != 4) {
                _exit(9);
            }
            if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)) {
                /* The child process is exited. */
                break;
            }
        }
    }
}
#ifndef STATIC

/* Start the forkserver from a constructor rather than from a __libc_start_main
 * hook. Runs after the dynamic linker has already finished relocation, but
 * before the traced binary's own constructors and its main(). Raises a single
 * SIGSTOP under cs-trace, and is a no-op otherwise. */
__attribute__((constructor))
static void __cs_forkserver_ctor(void) {
    __cs_start_forkserver();
}
#endif
