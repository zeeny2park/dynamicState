/* IMP-009 fixture: an overrun of a live heap buffer into a FREED neighbour that sits in the tcache: the
 * neighbour's size field and its tcache next pointer (safe-linked on glibc >= 2.32) are overwritten.  The
 * write is done once; the process then idles and never calls malloc/free again (the damaged tcache bin is
 * never used, so glibc does not abort).
 *
 *   g_src   = malloc(40): chunk 48, usable 40; 64 bytes are written -> 24 bytes past the usable end:
 *             the freed neighbour's size (8), tcache next (8) and tcache key (8)
 *   g_stale = malloc(40), then freed (pointer kept: it is the freed neighbour)
 *   g_tail  = malloc(40): keeps g_stale away from top
 *
 * Prints: OVERRUN g_src <user addr> <usable> 24 g_stale <freed user addr>, then READY.
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *g_src;
char *g_stale;
char *g_tail;

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 14);
    g_src = malloc(40);
    g_stale = malloc(40);
    g_tail = malloc(40);
    memset(g_tail, 't', 40);
    size_t usable = malloc_usable_size(g_src);
    printf("OVERRUN g_src %p %zu 24 g_stale %p\n", (void *)g_src, usable, (void *)g_stale);
    fflush(stdout);
    free(g_stale);
    memset(g_src, 'S', usable + 24);
    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
