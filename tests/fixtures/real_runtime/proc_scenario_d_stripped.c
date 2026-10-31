/*
 * proc_scenario_d_stripped.c
 * Stripped / Constrained Target for Adaptive Investigation Phase 2.0-A.3.1
 * Compiled without DWARF debug information, forcing engine to detect capability deficit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void *worker_fn(void *arg) {
    (void)arg;
    while (g_running) {
        usleep(30000);
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    pthread_t th;
    if (pthread_create(&th, NULL, worker_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[SCENARIO_D] PID %d stripped running\n", getpid());
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    pthread_join(th, NULL);
    return 0;
}
