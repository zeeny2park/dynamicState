/*
 * proc_scenario_a_healthy.c
 * Deterministic Healthy Process for Adaptive Investigation Phase 2.0-A.3.1
 * Multi-threaded process with normal workload cycles, valid memory bounds,
 * and no synchronization stalls or memory leaks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t g_running = 1;
static volatile uint64_t g_worker1_ticks = 0;
static volatile uint64_t g_worker2_ticks = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void *worker_compute_thread(void *arg) {
    (void)arg;
    uint64_t a = 0, b = 1;
    while (g_running) {
        uint64_t next = a + b;
        a = b;
        b = next;
        g_worker1_ticks++;
        if (g_worker1_ticks % 1000 == 0) {
            a = 0;
            b = 1;
        }
        usleep(15000); /* 15ms work cycle */
    }
    return NULL;
}

static void *worker_timer_thread(void *arg) {
    (void)arg;
    while (g_running) {
        g_worker2_ticks++;
        usleep(25000); /* 25ms timer cycle */
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    pthread_t th1, th2;
    if (pthread_create(&th1, NULL, worker_compute_thread, NULL) != 0) {
        perror("pthread_create th1");
        return 1;
    }
    if (pthread_create(&th2, NULL, worker_timer_thread, NULL) != 0) {
        perror("pthread_create th2");
        return 1;
    }

    /* Small static buffer to keep heap minimal and stable */
    char *stable_buf = (char *)malloc(1024 * 64);
    if (stable_buf) {
        stable_buf[0] = 'H';
    }

    printf("[SCENARIO_A] PID %d healthy running (worker1=%lu, worker2=%lu)\n",
           getpid(), (unsigned long)g_worker1_ticks, (unsigned long)g_worker2_ticks);
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    pthread_join(th1, NULL);
    pthread_join(th2, NULL);
    if (stable_buf) free(stable_buf);
    return 0;
}
