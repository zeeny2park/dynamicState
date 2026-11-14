/*
 * proc_scenario_b_growing_mem.c
 * Deterministic Memory Growth Process for Adaptive Investigation Phase 2.0-A.3.1
 * Continuously expands memory without releasing, triggering heap/mapping growth.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t g_running = 1;
static volatile size_t g_total_allocated = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void *leak_worker_thread(void *arg) {
    (void)arg;
    while (g_running) {
        /* Allocate 1MB and touch pages to ensure physical mapping */
        size_t chunk_size = 1024 * 1024;
        volatile char *ptr = (volatile char *)malloc(chunk_size);
        if (ptr) {
            for (size_t i = 0; i < chunk_size; i += 4096) {
                ptr[i] = (char)(i & 0xFF);
            }
            g_total_allocated += chunk_size;
        }
        usleep(30000); /* 30ms allocation cycle */
        /* FIXTURE_CAP: ~32 MiB/s measured (975 MiB resident after 30 s, 39 GB after 20 min). Stop allocating at
         * 1 GiB (~31 s, well above anything a test or benchmark observes: the accuracy benchmark diagnoses at
         * 6-25 s); the leaked memory stays, the process stays alive. */
        if (g_total_allocated >= (1024UL << 20)) {
            while (g_running) usleep(50000);
        }
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    /* Initial 6MB allocation so triage immediately flags memory growth candidate */
    for (int i = 0; i < 6; i++) {
        size_t init_chunk = 1024 * 1024;
        char *init_ptr = (char *)malloc(init_chunk);
        if (init_ptr) {
            memset(init_ptr, 0xAA, init_chunk);
            g_total_allocated += init_chunk;
        }
    }

    pthread_t th;
    if (pthread_create(&th, NULL, leak_worker_thread, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[SCENARIO_B] PID %d memory growth running (allocated=%zu bytes)\n",
           getpid(), g_total_allocated);
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    pthread_join(th, NULL);
    return 0;
}
