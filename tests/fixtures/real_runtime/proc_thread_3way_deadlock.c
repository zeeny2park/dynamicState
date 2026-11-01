/*
 * proc_thread_3way_deadlock.c
 * 3-Thread Circular Deadlock Fixture for Phase 2.0-A.3.3
 * Thread 1 locks mutex A, waits for mutex B
 * Thread 2 locks mutex B, waits for mutex C
 * Thread 3 locks mutex C, waits for mutex A
 * Proves genuine multi-thread circular wait-for cycle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

static volatile sig_atomic_t g_running = 1;

static pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_c = PTHREAD_MUTEX_INITIALIZER;

static void handle_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

static void *worker_1(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex_a);
    usleep(30000);
    pthread_mutex_lock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_a);
    return NULL;
}

static void *worker_2(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex_b);
    usleep(30000);
    pthread_mutex_lock(&g_mutex_c);
    pthread_mutex_unlock(&g_mutex_c);
    pthread_mutex_unlock(&g_mutex_b);
    return NULL;
}

static void *worker_3(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex_c);
    usleep(30000);
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_c);
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th1, th2, th3;
    if (pthread_create(&th1, NULL, worker_1, NULL) != 0 ||
        pthread_create(&th2, NULL, worker_2, NULL) != 0 ||
        pthread_create(&th3, NULL, worker_3, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[PROC_3WAY_DEADLOCK] PID %d started (mutexes: %p, %p, %p)\n",
           getpid(), (void *)&g_mutex_a, (void *)&g_mutex_b, (void *)&g_mutex_c);
    fflush(stdout);

    while (g_running) {
        pause();
    }

    return 0;
}
