/* Double free that survives glibc's checks: with the tcache for the size full, free(a), free(b), free(a)
 * leaves fastbin a -> b -> a (glibc only compares the fastbin head).  g_last still points at a.
 * Prints READY, then idles without calling malloc/free again. */
#include <stdlib.h>
#include <unistd.h>

struct msg { struct msg *next; int id; char body[40]; };
static struct msg *g_last;

int main(void)
{
    struct msg *fill[7];
    struct msg *a = malloc(sizeof *a), *b = malloc(sizeof *b);
    for (int i = 0; i < 7; i++)
        fill[i] = malloc(sizeof(struct msg));
    for (int i = 0; i < 7; i++)
        free(fill[i]);                 /* tcache for this size is now full */
    g_last = a;
    free(a);
    free(b);
    free(a);                           /* the double free */
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
