#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

pthread_mutex_t g_mutex_A = PTHREAD_MUTEX_INITIALIZER;
char g_padding[128];
pthread_mutex_t g_mutex_B = PTHREAD_MUTEX_INITIALIZER;

volatile int g_ready_A = 0;
volatile int g_ready_B = 0;

__attribute__((noinline)) void worker_A_work() {
    pthread_mutex_lock(&g_mutex_A);
    g_ready_A = 1;
    printf("[Thread A] Acquired g_mutex_A, waiting for Thread B...\n");
    fflush(stdout);

    while (!g_ready_B) usleep(1000);

    printf("[Thread A] Attempting to acquire g_mutex_B (will deadlock)...\n");
    fflush(stdout);
    pthread_mutex_lock(&g_mutex_B); // Deadlock!

    pthread_mutex_unlock(&g_mutex_B);
    pthread_mutex_unlock(&g_mutex_A);
}

__attribute__((noinline)) void worker_B_work() {
    pthread_mutex_lock(&g_mutex_B);
    g_ready_B = 1;
    printf("[Thread B] Acquired g_mutex_B, waiting for Thread A...\n");
    fflush(stdout);

    while (!g_ready_A) usleep(1000);

    printf("[Thread B] Attempting to acquire g_mutex_A (will deadlock)...\n");
    fflush(stdout);
    pthread_mutex_lock(&g_mutex_A); // Deadlock!

    pthread_mutex_unlock(&g_mutex_A);
    pthread_mutex_unlock(&g_mutex_B);
}

void* thread_A_func(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "worker_A");
    worker_A_work();
    return NULL;
}

void* thread_B_func(void* arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "worker_B");
    worker_B_work();
    return NULL;
}

int main() {
    printf("=== Deadlock Demo Process Started (PID: %d) ===\n", getpid());
    fflush(stdout);

    pthread_t thA, thB;
    pthread_create(&thA, NULL, thread_A_func, NULL);
    pthread_create(&thB, NULL, thread_B_func, NULL);

    pthread_join(thA, NULL);
    pthread_join(thB, NULL);
    return 0;
}
