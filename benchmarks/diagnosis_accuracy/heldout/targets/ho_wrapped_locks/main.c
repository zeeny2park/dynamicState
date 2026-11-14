/* A block cache in front of a disk: eviction writes back under the cache lock, loading fills under the disk lock. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include "sync.h"

pthread_mutex_t cache_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t disk_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t both_in;
volatile long cached_blocks, disk_writes;

static void *evictor(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "evictor");
    take(&cache_mu);
    pthread_barrier_wait(&both_in);
    take(&disk_mu);
    disk_writes++;
    cached_blocks--;
    give(&disk_mu);
    give(&cache_mu);
    return NULL;
}

static void *loader(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "loader");
    take(&disk_mu);
    pthread_barrier_wait(&both_in);
    take(&cache_mu);
    cached_blocks++;
    give(&cache_mu);
    give(&disk_mu);
    return NULL;
}

int main(void)
{
    pthread_t a, b;
    pthread_barrier_init(&both_in, NULL, 2);
    pthread_create(&a, NULL, evictor, NULL);
    pthread_create(&b, NULL, loader, NULL);
    usleep(600000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
