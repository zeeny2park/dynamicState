/*
 * Circular deadlock whose lock calls sit in a small static function that is force-inlined
 * (exercises the inlined-subroutine chain of the line table at -O2).
 * Thread 1 locks A then B, thread 2 locks B then A.
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

static pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;

static inline __attribute__((always_inline)) void lock_pair(pthread_mutex_t *first, pthread_mutex_t *second) {
    pthread_mutex_lock(first);
    usleep(25000);
    pthread_mutex_lock(second);
}

__attribute__((noinline)) static void *worker_1(void *arg) {
    (void)arg;
    lock_pair(&g_mutex_a, &g_mutex_b);
    return NULL;
}

__attribute__((noinline)) static void *worker_2(void *arg) {
    (void)arg;
    lock_pair(&g_mutex_b, &g_mutex_a);
    return NULL;
}

int main(void) {
    pthread_t th1, th2;
    pthread_create(&th1, NULL, worker_1, NULL);
    pthread_create(&th2, NULL, worker_2, NULL);
    printf("[INLINED_DEADLOCK] PID %d started\n", getpid());
    fflush(stdout);
    for (;;) pause();
    return 0;
}
