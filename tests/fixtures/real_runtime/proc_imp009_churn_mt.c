/* IMP-009 healthy fixture (torn-read stress): four threads malloc / calloc / realloc / free continuously in
 * their own arenas and the main arena, small (tcache / fastbin) and large (unsorted / small / large bins)
 * sizes, while the process is diagnosed.  Nothing is ever written out of bounds.  Prints READY. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 256

struct worker {
    void *volatile slot[SLOTS];
    size_t size[SLOTS];
    unsigned seed;
};

struct worker g_workers[4];

static void *run(void *arg)
{
    struct worker *w = arg;
    char name[16];
    snprintf(name, sizeof name, "churn%d", (int)(w - g_workers) & 7);
    pthread_setname_np(pthread_self(), name);
    for (;;) {
        w->seed = w->seed * 1103515245u + 12345u;
        unsigned i = (w->seed >> 8) % SLOTS;
        unsigned r = (w->seed >> 4) & 0xff;
        size_t sz = r < 200 ? 16 + (w->seed >> 12) % 480 : 1024 + (w->seed >> 12) % 6000;
        void *old = w->slot[i];
        if (old && (r & 3) == 0) {
            void *n = realloc(old, sz);
            if (n) {
                w->slot[i] = n;
                w->size[i] = sz;
                memset(n, (int)r, sz);
            }
            continue;
        }
        w->slot[i] = NULL;
        free(old);
        void *p = (r & 1) ? calloc(1, sz) : malloc(sz);
        if (p) {
            memset(p, (int)r, sz);
            w->size[i] = sz;
        }
        w->slot[i] = p;
    }
    return NULL;
}

int main(void)
{
    pthread_t t[3];
    for (int k = 0; k < 4; k++)
        g_workers[k].seed = 17u * (unsigned)k + 3u;
    for (int k = 0; k < 3; k++)
        pthread_create(&t[k], NULL, run, &g_workers[k + 1]);
    printf("READY\n");
    fflush(stdout);
    run(&g_workers[0]);
    return 0;
}
