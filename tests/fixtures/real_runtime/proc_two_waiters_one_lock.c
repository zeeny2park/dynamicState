/*
 * proc_two_waiters_one_lock.c
 * Multiple Waiters on One Lock (Contention without Deadlock Cycle)
 * Thread 1 holds mutex M.
 * Thread 2 and Thread 3 both wait on mutex M.
 * Both waiters point to Thread 1. No cycle exists!
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

static volatile sig_atomic_t g_running = 1;
static pthread_mutex_t g_single_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_holder_ready = 0;
static volatile int g_waiters_started = 0;

static void handle_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

static void *holder_fn(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_single_mutex);
    g_holder_ready = 1;
    while (g_running) {
        usleep(50000);
    }
    pthread_mutex_unlock(&g_single_mutex);
    return NULL;
}

static void *waiter_fn(void *arg) {
    (void)arg;
    while (!g_holder_ready && g_running) {
        usleep(5000);
    }
    __sync_fetch_and_add(&g_waiters_started, 1);
    pthread_mutex_lock(&g_single_mutex);
    pthread_mutex_unlock(&g_single_mutex);
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th_holder, th_w1, th_w2;
    if (pthread_create(&th_holder, NULL, holder_fn, NULL) != 0 ||
        pthread_create(&th_w1, NULL, waiter_fn, NULL) != 0 ||
        pthread_create(&th_w2, NULL, waiter_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    while (g_waiters_started < 2 && g_running) {
        usleep(5000);
    }
    usleep(25000); // Allow kernel to place waiters in futex wait

    printf("[PROC_TWO_WAITERS_ONE_LOCK] PID %d started (mutex: %p)\n",
           getpid(), (void *)&g_single_mutex);
    fflush(stdout);

    while (g_running) {
        pause();
    }

    return 0;
}
