/* Hit/miss statistics; every operation runs inside a locked section. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

#define WITH_STATS(body)                    \
    do {                                    \
        pthread_mutex_lock(&stats_mu);      \
        body;                               \
        pthread_mutex_unlock(&stats_mu);    \
    } while (0)

static pthread_mutex_t stats_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long hits, misses;

static unsigned long total(void)
{
    unsigned long t;
    WITH_STATS(t = hits + misses);
    return t;
}

static void record_hit(void)
{
    WITH_STATS(hits++; if (total() % 1000 == 0) misses = 0);
}

static void *stats_thread(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "stats");
    for (;;) {
        record_hit();
        usleep(1000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, stats_thread, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
