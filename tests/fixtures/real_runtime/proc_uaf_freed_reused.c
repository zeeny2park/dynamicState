/* Healthy use-after-free control: a chunk freed and immediately re-allocated.  g_old keeps the old pointer,
 * which (same size, LIFO tcache) is exactly the new block g_new: the chunk is IN USE again, so writes through
 * either pointer are writes into a live block.  Nothing is freed after READY.
 * Prints: REUSED <same: 1|0>, then READY.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct item {
    long key;
    long value;
    char tag[40];
};

struct item *g_old;
struct item *g_new;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    g_old = malloc(sizeof *g_old);          /* malloc, not calloc: calloc bypasses the tcache */
    memset(g_old, 0, sizeof *g_old);
    free(g_old);
    g_new = malloc(sizeof *g_new);          /* same size: takes the chunk just freed (LIFO tcache) */
    memset(g_new, 0, sizeof *g_new);
    printf("REUSED %d\n", g_old == g_new);
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (long n = 0;; n++) {
        g_old->value = n;                   /* the block is live (re-allocated): not a use after free */
        g_new->key = n;
        nanosleep(&ts, NULL);
    }
}
