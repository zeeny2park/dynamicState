/* IMP-008 fixture: an ingest thread allocates a record per event, uses it and drops the pointer (never freed).
 * Ground truth: unreachable blocks of request size sizeof(struct record), allocated by thread "ingest".
 * Prints the ground truth and READY, then keeps leaking. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct record {
    char key[40];
    double vals[18];
    unsigned flags;
};

static volatile unsigned long g_events;
static volatile double g_sum;

static void consume(struct record *r)
{
    g_sum += r->vals[0] + r->vals[17];
}

static void *ingest(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "ingest");
    for (;;) {
        struct record *r = malloc(sizeof *r);
        if (!r)
            break;
        memset(r, 0, sizeof *r);
        r->vals[0] = (double)g_events;
        consume(r);
        g_events++;          /* r goes out of scope here: dropped pointer */
        usleep(500);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, ingest, NULL);
    while (g_events < 300)
        usleep(10000);
    printf("GT leak_request_size=%zu thread=ingest\nREADY\n", sizeof(struct record));
    fflush(stdout);
    for (;;)
        pause();
}
