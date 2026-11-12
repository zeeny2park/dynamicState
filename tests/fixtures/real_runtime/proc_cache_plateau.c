/* IMP-008 fixture: a bounded cache fills up (warm-up), then replaces entries (free old, allocate new) at a
 * constant size.  Ground truth: no leak.  Prints READY once the cache is full and has been churning. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 512

struct entry {
    unsigned key;
    char data[480];
};

static struct entry *g_cache_slots[SLOTS];
static volatile unsigned g_puts;

static void *filler(void *arg)
{
    unsigned k = 0;
    (void)arg;
    pthread_setname_np(pthread_self(), "filler");
    for (;;) {
        unsigned s = (k * 2654435761u) % SLOTS;
        struct entry *e = malloc(sizeof *e);
        if (e) {
            e->key = k;
            memset(e->data, (int)k, sizeof e->data);
            free(g_cache_slots[s]);
            g_cache_slots[s] = e;
        }
        k++;
        g_puts++;
        usleep(300);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, filler, NULL);
    while (g_puts < 4 * SLOTS)
        usleep(10000);
    printf("GT leak=none\nREADY\n");
    fflush(stdout);
    for (;;)
        pause();
}
