/* Tcache double free.  glibc >= 2.29 aborts free(a); free(a) because a's tcache key word matches; here the key
 * word is cleared between the two frees - this memset SIMULATES the effect of a stray write into the freed
 * block (a real use-after-free overwrite) and is not a normal program action.  Result: tcache a -> b -> a with
 * count 3.  g_last still points at a.  Prints READY, then idles without calling malloc/free again. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct msg { struct msg *next; int id; char body[40]; };
static struct msg *g_last;

int main(void)
{
    struct msg *a = malloc(sizeof *a);
    struct msg *b = malloc(sizeof *b);
    g_last = a;
    free(a);
    free(b);
    memset((char *)a + 8, 0, 8);       /* simulated overwrite of the tcache key word */
    free(a);                           /* the double free */
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
