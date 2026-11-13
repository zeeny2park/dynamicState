/* Four request handlers serialise on one connection-table lock; the holder spends about 3 ms per request
 * under it and the handlers have almost no other work, so at any moment most of them are queued. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t conn_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long served;

static void spin_ms(long ms)
{
    struct timespec t0, t;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        for (volatile int i = 0; i < 1000; i++)
            ;
        clock_gettime(CLOCK_MONOTONIC, &t);
    } while ((t.tv_sec - t0.tv_sec) * 1000000000L + (t.tv_nsec - t0.tv_nsec) < ms * 1000000L);
}

static void *handler(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "handler");
    for (;;) {
        pthread_mutex_lock(&conn_mu);
        spin_ms(3);
        served++;
        pthread_mutex_unlock(&conn_mu);
        usleep(200);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, handler, NULL);
    while (served < 10)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
