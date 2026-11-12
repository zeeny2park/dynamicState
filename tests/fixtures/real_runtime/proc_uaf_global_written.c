/* Use-after-free fixture (a): a global pointer kept after free(), written through periodically.
 *
 *   g_current = calloc(struct record)   (64 bytes -> chunk 80, tcache)
 *   free(g_current)                     -> the chunk sits in the tcache; g_current still points to it
 *   every 20 ms: g_current->hits++, g_current->flags = n   (offsets 48 / 56: beyond the tcache metadata)
 *
 * Only offsets >= 16 are written, so the tcache next pointer / key stay intact (glibc never notices) and the
 * chunk stays free: no malloc/free is made after READY.  Neighbours keep it away from top.
 * Prints: UAF g_current <freed user addr> 80, then READY.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct record {
    long id;
    long seq;
    char name[32];
    long hits;
    long flags;
};

struct record *g_current;
struct record *g_before;
struct record *g_after;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    g_before = calloc(1, sizeof *g_before);
    g_current = calloc(1, sizeof *g_current);
    g_after = calloc(1, sizeof *g_after);
    g_current->id = 7;
    strcpy(g_current->name, "current-record");
    printf("UAF g_current %p 80\n", (void *)g_current);
    free(g_current);                      /* the bug: the pointer is kept */
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (long n = 1;; n++) {
        g_current->hits++;                /* use after free (offset 48) */
        g_current->flags = n;             /* offset 56 */
        nanosleep(&ts, NULL);
    }
}
