/* IMP-008 fixture: memory rises then falls, over and over (batch working set held by the batch function,
 * released at the end of each batch).  Ground truth: no leak.  Prints READY after the first batch. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NBLK 40
#define BLK (64 * 1024)

static volatile unsigned g_batches;

static void run_batch(void)
{
    void *blk[NBLK];
    for (int i = 0; i < NBLK; i++) {
        blk[i] = malloc(BLK);
        if (blk[i])
            memset(blk[i], i, BLK);
        usleep(10000);
    }
    for (int i = 0; i < NBLK; i++)
        free(blk[i]);
}

static void *batcher(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "batcher");
    for (;;) {
        run_batch();
        g_batches++;
        usleep(100000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, batcher, NULL);
    while (g_batches < 1)
        usleep(10000);
    printf("GT leak=none\nREADY\n");
    fflush(stdout);
    for (;;)
        pause();
}
