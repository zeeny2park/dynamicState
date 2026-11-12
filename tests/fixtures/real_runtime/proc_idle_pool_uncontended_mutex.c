/*
 * IMP-010 regression fixture: a healthy idle worker pool.
 * Three workers wait on a condition variable for work that never arrives (idle, nothing wrong).
 * g_stats_mutex is a separate, genuinely uncontended mutex: the main thread locks and unlocks it a few
 * times per second and nobody ever waits on it.
 * Prints READY once all workers are parked.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>

#define NW 3
static pthread_mutex_t g_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_queue_cv = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_queue_len;
static long g_stats;
static volatile int g_parked;

static void on_term(int s) { (void)s; _exit(0); }

static void *idle_worker(void *a)
{
    (void)a;
    prctl(PR_SET_NAME, "idle_worker");
    pthread_mutex_lock(&g_queue_mutex);
    for (;;) {
        while (g_queue_len == 0) {
            g_parked++;
            pthread_cond_wait(&g_queue_cv, &g_queue_mutex);
            g_parked--;
        }
        g_queue_len--;
    }
    return NULL;
}

int main(void)
{
    pthread_t t[NW];
    signal(SIGTERM, on_term);
    for (int i = 0; i < NW; i++)
        pthread_create(&t[i], NULL, idle_worker, NULL);
    while (g_parked < NW)
        usleep(10000);
    printf("READY\n");
    fflush(stdout);
    for (;;) {
        pthread_mutex_lock(&g_stats_mutex);
        g_stats++;
        pthread_mutex_unlock(&g_stats_mutex);
        usleep(100000);
    }
}
