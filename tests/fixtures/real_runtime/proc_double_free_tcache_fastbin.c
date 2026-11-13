/* Double free onto two lists: tcache for the size full, free(a) goes to a fastbin; seven allocations drain the
 * tcache; free(a) again goes into the tcache (its key word holds no tcache key, so glibc does not look).
 * a is then on the tcache bin and the fastbin.  g_last still points at a.
 * Prints READY, then idles without calling malloc/free again. */
#include <stdlib.h>
#include <unistd.h>

struct msg { struct msg *next; int id; char body[40]; };
static struct msg *g_last;
static struct msg *g_hold[7];

int main(void)
{
    struct msg *a = malloc(sizeof *a);
    for (int i = 0; i < 7; i++)
        g_hold[i] = malloc(sizeof(struct msg));
    for (int i = 0; i < 7; i++)
        free(g_hold[i]);
    g_last = a;
    free(a);
    for (int i = 0; i < 7; i++)
        g_hold[i] = malloc(sizeof(struct msg));
    free(a);                           /* the double free */
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
