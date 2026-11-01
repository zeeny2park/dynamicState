/*
 * Real Native Linux Process Fixture: Deterministic Circular Deadlock
 * Thread 1 locks mutex A then waits for mutex B.
 * Thread 2 locks mutex B then waits for mutex A.
 * Demonstrates confirmed circular wait and lock contention.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

static volatile sig_atomic_t g_running = 1;

static pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;

static void handle_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

static void *worker_1(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex_a);
    usleep(25000); // 25ms window to ensure worker_2 acquires mutex_b
    pthread_mutex_lock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_a);
    return NULL;
}

static void *worker_2(void *arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex_b);
    usleep(25000); // 25ms window to ensure worker_1 acquires mutex_a
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_b);
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th1, th2;
    if (pthread_create(&th1, NULL, worker_1, NULL) != 0 ||
        pthread_create(&th2, NULL, worker_2, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    printf("[PROC_CIRCULAR_DEADLOCK] PID %d started\n", getpid());
    fflush(stdout);

    while (g_running) {
        pause();
    }

    return 0;
}
