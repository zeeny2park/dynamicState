/* IMP-007 fixture: heap under constant concurrent modification (torn-read exposure).
 * Two threads continuously allocate and free blocks of varying sizes in the main arena and in a
 * thread arena while the walker reads; a stable global list keeps a known set of blocks alive.
 * Prints BLOCK <addr> <size> <path> for the stable blocks, then READY, then keeps churning. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 512

void *g_stable[32];
void *volatile g_churn_main[SLOTS];
void *volatile g_churn_thr[SLOTS];

static void churn(void *volatile *slots, unsigned seed)
{
    for (;;) {
        seed = seed * 1103515245u + 12345u;
        unsigned i = (seed >> 8) % SLOTS;
        size_t sz = 16 + ((seed >> 4) % 2000);
        void *old = slots[i];
        slots[i] = NULL;
        free(old);
        void *p = malloc(sz);
        if (p)
            memset(p, (int)(seed & 0xff), sz < 32 ? sz : 32);
        slots[i] = p;
    }
}

static void *churner(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "churner");
    churn(g_churn_thr, 99);
    return NULL;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    for (int i = 0; i < 32; i++) {
        g_stable[i] = malloc(100 + i);
        memset(g_stable[i], 0x5a, 100 + i);
    }
    for (int i = 0; i < 32; i++)
        printf("BLOCK %p %d g_stable[%d]\n", g_stable[i], 100 + i, i);
    pthread_t th;
    pthread_create(&th, NULL, churner, NULL);
    printf("READY\n");
    fflush(stdout);
    churn(g_churn_main, 7);
    return 0;
}
