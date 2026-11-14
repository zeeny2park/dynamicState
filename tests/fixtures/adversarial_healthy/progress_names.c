/* Healthy, idle by design (waits for requests that never come).  Variables named like progress / heartbeat /
 * stall indicators that do not change because nothing is asked of the program, plus a worker blocked in a
 * condition variable wait and one in poll(). */
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
long heartbeat_counter = 42;
long progress = 0;
long processed_total = 0;
int stalled = 1;          /* a configuration flag: "allow stalled clients" */
int watchdog_ticks = 0;
pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
int g_has_work = 0;
static void *worker(void *a) {
    (void)a;
    pthread_mutex_lock(&g_mu);
    while (!g_has_work) pthread_cond_wait(&g_cv, &g_mu);
    pthread_mutex_unlock(&g_mu);
    return 0;
}
static void *poller(void *a) {
    (void)a;
    for (;;) poll(0, 0, 60000);
    return 0;
}
int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, worker, 0);
    pthread_create(&t2, 0, poller, 0);
    printf("READY\n"); fflush(stdout);
    for (;;) pause();
}
