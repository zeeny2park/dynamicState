/* Use-after-free fixture: freed memory written while no typed pointer to it remains.
 *
 *   a = malloc(72), b = malloc(72) (chunks 80); free(a); free(b)  -> tcache bin: b (head), a (entry 1)
 *   the address of a is kept only XOR-encoded in an integer (g_cookie): no typed pointer refers to it
 *   every 20 ms: ((long *)a)[5] = n   (offset 40, beyond the tcache metadata)
 *
 * a is not the head of its list, so an immediate re-allocation is structurally excluded.  No malloc/free after
 * READY.  Prints: UNREF <freed user addr of a> 80, then READY.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uintptr_t g_cookie;
char *g_guard;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    char *a = malloc(72);
    char *b = malloc(72);
    g_guard = malloc(72);
    memset(a, 'a', 72);
    memset(b, 'b', 72);
    g_cookie = (uintptr_t)a ^ (uintptr_t)0x5a5a5a5a5a5aUL;
    printf("UNREF %p 80\n", (void *)a);
    free(a);
    free(b);
    a = b = NULL;
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (long n = 1;; n++) {
        long *p = (long *)(g_cookie ^ (uintptr_t)0x5a5a5a5a5a5aUL);
        p[5] = n;                               /* use after free, no typed pointer left */
        nanosleep(&ts, NULL);
    }
}
