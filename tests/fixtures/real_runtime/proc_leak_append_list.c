/* IMP-008 fixture: a producer thread only ever appends to a global singly linked list (never removes).
 * Ground truth: the growing owner is the global g_pending_items, the allocating thread is "producer".
 * Prints the ground truth and READY once the list holds a few hundred items, then keeps appending. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct item {
    struct item *next;
    unsigned seq;
    char payload[200];
};

static struct item *g_pending_items;
static struct item *g_pending_tail;
static volatile unsigned g_count;

static void *producer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "producer");
    for (;;) {
        struct item *it = calloc(1, sizeof *it);
        if (!it)
            break;
        it->seq = g_count;
        if (g_pending_tail)
            g_pending_tail->next = it;
        else
            g_pending_items = it;
        g_pending_tail = it;
        g_count++;
        usleep(500);
        /* FIXTURE_CAP: ~0.36 MiB/s measured; stop appending at ~220 MiB (~10 min), stay alive. */
        if (g_count >= 1000000u)
            for (;;) pause();
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, producer, NULL);
    while (g_count < 300)
        usleep(10000);
    printf("GT owner=g_pending_items thread=producer item_size=%zu\nREADY\n", sizeof(struct item));
    fflush(stdout);
    for (;;)
        pause();
}
