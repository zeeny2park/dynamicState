/* Healthy, steady memory.  Structs with a pointer and ever-increasing integers (monotonic ring indices, event
 * totals): the layout of a pointer+count container, but the counts are not element counts and no memory grows
 * with them.  Globals with a capacity word and a length word that only share a one-letter prefix. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct Ring { int *data; unsigned long produced; unsigned long consumed; unsigned int mask; };
struct Ring g_ring;
struct Events { char *name; long total; long dropped; } g_events = { "events", 0, 0 };
int g_limit = 1;
int g_used = 5;
long s_max = 2;
long s_count = 9;
int main(void) {
    g_ring.data = calloc(1024, sizeof(int));
    g_ring.mask = 1023;
    printf("READY\n"); fflush(stdout);
    for (;;) {
        g_ring.data[g_ring.produced & g_ring.mask] = 1;
        g_ring.produced += 7;
        g_ring.consumed += 7;
        g_events.total += 3;
        usleep(1000);
    }
}
