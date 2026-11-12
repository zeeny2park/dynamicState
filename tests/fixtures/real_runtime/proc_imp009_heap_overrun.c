/* IMP-009 fixture: a heap buffer is written 8 bytes past its end, once; then the process idles without
 * calling malloc/free again (glibc never re-validates the damaged header, so it does not abort).
 *
 *   g_label = malloc(40)  -> chunk 48, usable 40 (LP64): 48 bytes are written -> the 8 bytes after the
 *                            usable end are the NEXT chunk's size field
 *   g_peer  = malloc(40)  -> the damaged (victim) chunk
 *   g_small = malloc(20)  -> usable 24: a 21-byte write (off by one) stays in the slack: invisible
 *   g_after = malloc(40)  -> neighbour of g_small, intact
 *
 * Prints ground truth then READY:
 *   OVERRUN <buffer var> <user addr> <usable> <bytes past usable end> <victim var> <victim user addr>
 *   SLACK <var> <user addr> <requested> <written>
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *g_label;
char *g_peer;
char *g_small;
char *g_after;

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 14);
    g_label = malloc(40);
    g_peer = malloc(40);
    g_small = malloc(20);
    g_after = malloc(40);
    memset(g_peer, 'p', 40);
    memset(g_after, 'q', 40);
    size_t usable = malloc_usable_size(g_label);
    printf("OVERRUN g_label %p %zu 8 g_peer %p\n", (void *)g_label, usable, (void *)g_peer);
    printf("SLACK g_small %p 20 21 usable %zu\n", (void *)g_small, malloc_usable_size(g_small));
    fflush(stdout);
    memset(g_label, 'L', usable + 8);          /* the bad write: 8 bytes past the usable end */
    strcpy(g_small, "abcdefghijklmnopqrst"); /* 20 chars + NUL = 21 bytes into malloc(20) */
    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
