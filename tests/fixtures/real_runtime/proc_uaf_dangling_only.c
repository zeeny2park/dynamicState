/* Use-after-free fixture (c): a dangling global pointer that is NOT used after free.
 *
 *   g_last_msg = malloc(200) (chunk 208, tcache), filled, freed; the pointer is kept but never dereferenced.
 *   g_live     = malloc(200), in use and rewritten every 20 ms (a legitimate write).
 *
 * Expected: a candidate (dangling pointer, no write observed), never a confirmed fault.
 * Prints: DANGLING g_last_msg <freed user addr> 208, then READY.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *g_last_msg;
char *g_live;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    g_last_msg = malloc(200);
    g_live = malloc(200);
    memset(g_last_msg, 'm', 199);
    g_last_msg[199] = 0;
    printf("DANGLING g_last_msg %p 208\n", (void *)g_last_msg);
    free(g_last_msg);                     /* pointer kept, never used again */
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (unsigned n = 0;; n++) {
        memset(g_live, 'a' + (int)(n % 26), 199);
        nanosleep(&ts, NULL);
    }
}
