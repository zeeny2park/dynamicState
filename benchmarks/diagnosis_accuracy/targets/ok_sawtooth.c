/* Batch processing: memory climbs to ~100 MB per batch and is released after each one. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NB 50
#define SZ (2u << 20)

static volatile int batches;

static void *batcher(void *arg)
{
    void *blk[NB];
    (void)arg;
    pthread_setname_np(pthread_self(), "batcher");
    for (;;) {
        for (int i = 0; i < NB; i++) {
            blk[i] = malloc(SZ);
            if (blk[i])
                memset(blk[i], i, SZ);
            usleep(20000);
        }
        for (int i = 0; i < NB; i++)
            free(blk[i]);
        batches++;
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, batcher, NULL);
    while (batches < 1)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
