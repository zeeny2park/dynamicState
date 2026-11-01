/*
 * Real Native Linux Process Fixture: Normal Condition Variable / Futex Wait
 * Worker thread waits on pthread_cond_timedwait with regular periodic wakeup
 * and forward progress. Demonstrates that futex wait does NOT equal deadlock or stall.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

static volatile sig_atomic_t g_running = 1;
static volatile unsigned long g_progress_counter = 0;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;

static void handle_sigterm(int sig) {
    (void)sig;
    g_running = 0;
}

static void *worker_thread(void *arg) {
    (void)arg;
    struct timespec ts;

    while (g_running) {
        pthread_mutex_lock(&g_mutex);
        clock_gettime(CLOCK_REALTIME, &ts);
        // Wait 30ms on condition variable
        ts.tv_nsec += 30000000;
        if (ts.tv_nsec >= 1000000000) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }
        pthread_cond_timedwait(&g_cond, &g_mutex, &ts);
        g_progress_counter++;
        pthread_mutex_unlock(&g_mutex);
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th;
    if (pthread_create(&th, NULL, worker_thread, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[PROC_NORMAL_CV] PID %d started\n", getpid());
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    pthread_join(th, NULL);
    return 0;
}
