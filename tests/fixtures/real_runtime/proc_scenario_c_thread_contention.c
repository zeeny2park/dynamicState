/*
 * proc_scenario_c_thread_contention.c
 * Deterministic Thread Contention Process for Adaptive Investigation Phase 2.0-A.3.1
 * Thread 1 acquires a mutex and retains it, while Thread 2 blocks on the lock in futex wait.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

static volatile sig_atomic_t g_running = 1;
static pthread_mutex_t g_contended_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_lock_acquired = 0;
static volatile int g_waiter_entered = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void *holder_thread_fn(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_contended_lock);
    g_lock_acquired = 1;
    /* Hold lock until process termination */
    while (g_running) {
        usleep(50000);
    }
    pthread_mutex_unlock(&g_contended_lock);
    return NULL;
}

static void *waiter_thread_fn(void *arg) {
    (void)arg;
    /* Wait for holder to acquire the lock first */
    while (!g_lock_acquired && g_running) {
        usleep(5000);
    }
    g_waiter_entered = 1;
    /* This will block in futex wait until holder releases or process exits */
    pthread_mutex_lock(&g_contended_lock);
    pthread_mutex_unlock(&g_contended_lock);
    return NULL;
}

int main(void) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    pthread_t th_holder, th_waiter;
    if (pthread_create(&th_holder, NULL, holder_thread_fn, NULL) != 0) {
        perror("pthread_create holder");
        return 1;
    }
    if (pthread_create(&th_waiter, NULL, waiter_thread_fn, NULL) != 0) {
        perror("pthread_create waiter");
        return 1;
    }

    while (!g_waiter_entered && g_running) {
        usleep(5000);
    }
    /* Allow kernel to put waiter into futex wait state */
    usleep(30000);

    printf("[SCENARIO_C] PID %d thread contention running (mutex=%p)\n",
           getpid(), (void *)&g_contended_lock);
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    pthread_cancel(th_waiter);
    pthread_join(th_holder, NULL);
    pthread_join(th_waiter, NULL);
    return 0;
}
