/* Memory-growth fixture: the large sawtooth of the benchmark's healthy control ok_sawtooth (a batch of 50 x 2 MB
 * blocks, ~100 MB, released after each batch) with a slow leak superimposed: every step of a batch also allocates
 * one 8000-byte record and drops the pointer (never freed, ~350 KB/s).  The heap is larger than the default
 * heap-walk byte budget.  Ground truth: a leak.  A diagnosis must never call this process HEALTHY.
 * Prints the ground truth and READY after the first batch, then keeps running. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NB 50
#define SZ (2u << 20)
#define LEAK_SZ 8000

static volatile int g_batches;
static volatile unsigned long g_sum;

static void leak_one(int i)
{
    char *r = malloc(LEAK_SZ);
    if (r) {
        memset(r, i, LEAK_SZ);
        g_sum += (unsigned char)r[7];
    }                                   /* r goes out of scope: dropped pointer */
}

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
            leak_one(i);
            usleep(20000);
        }
        for (int i = 0; i < NB; i++)
            free(blk[i]);
        g_batches++;
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
