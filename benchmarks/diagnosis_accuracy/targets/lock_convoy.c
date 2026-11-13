/* Six workers all queue on one mutex whose holder does a couple of milliseconds of work per turn: the lock is
 * always held, the holder always finishes and the next waiter gets it. Slow, but nothing is stuck. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t table_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long done_total;
static volatile unsigned long done_by[6];

static void hold_for_ms(long ms)
{
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (volatile int i = 0; i < 2000; i++)
            ;
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) * 1000000000L + (t.tv_nsec - t0.tv_nsec) < ms * 1000000L);
}

static void *worker(void *arg)
{
    int me = (int)(intptr_t)arg;
    pthread_setname_np(pthread_self(), "tbl_worker");
    for (;;) {
        pthread_mutex_lock(&table_mu);
        hold_for_ms(2);
        done_total++;
        done_by[me]++;
        pthread_mutex_unlock(&table_mu);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[6];
    for (intptr_t i = 0; i < 6; i++)
        pthread_create(&t[i], NULL, worker, (void *)i);
    while (done_total < 20)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
