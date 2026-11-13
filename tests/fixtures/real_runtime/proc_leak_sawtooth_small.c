/* Memory-growth fixture: a sawtooth working set (a batch of 40 x 64 KB blocks held by the batch function and
 * released at the end of each batch, as in proc_mem_rise_fall.c) with a slow leak superimposed: every step of a
 * batch also allocates one 2000-byte record and drops the pointer (never freed, ~150 KB/s).  The heap stays small
 * enough to walk.  Ground truth: a leak (unreachable blocks of request size LEAK_SZ, thread "batcher").
 * Prints the ground truth and READY after the first batch, then keeps running. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NBLK 40
#define BLK (64 * 1024)
#define LEAK_SZ 2000

static volatile unsigned g_batches;
static volatile unsigned long g_sum;

static void leak_one(int i)
{
    char *r = malloc(LEAK_SZ);
    if (r) {
        memset(r, i, LEAK_SZ);
        g_sum += (unsigned char)r[7];
    }                                   /* r goes out of scope: dropped pointer */
}

static void run_batch(void)
{
    void *blk[NBLK];
    for (int i = 0; i < NBLK; i++) {
        blk[i] = malloc(BLK);
        if (blk[i])
            memset(blk[i], i, BLK);
        leak_one(i);
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
        /* FIXTURE_CAP: leaks 80 KB per batch (~0.16 MiB/s measured); stop after 1500 batches (~120 MB, ~12 min),
         * stay alive. */
        if (g_batches >= 1500u)
            for (;;) pause();
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, batcher, NULL);
    while (g_batches < 1)
        usleep(10000);
    printf("GT leak=unreachable leak_request_size=%d thread=batcher\nREADY\n", LEAK_SZ);
    fflush(stdout);
    for (;;)
        pause();
}
