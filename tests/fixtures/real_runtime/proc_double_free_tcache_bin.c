/* Double free onto the tcache and a regular bin: tcache for 0x110 chunks full, free(a) goes to the unsorted bin;
 * seven malloc() calls drain the tcache; free(a) again goes into the tcache (its key word holds a bin pointer).
 * a is then in the tcache bin and the unsorted bin.  g_last still points at a.
 * Prints READY, then idles without calling malloc/free again. */
#include <stdlib.h>
#include <unistd.h>

static char *g_last;
static char *g_hold[7];

int main(void)
{
    char *a = malloc(0x100);
    for (int i = 0; i < 7; i++)
        g_hold[i] = malloc(0x100);
    for (int i = 0; i < 7; i++)
        free(g_hold[i]);
    g_last = a;
    free(a);
    for (int i = 0; i < 7; i++)
        g_hold[i] = malloc(0x100);
    free(a);                           /* the double free */
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
