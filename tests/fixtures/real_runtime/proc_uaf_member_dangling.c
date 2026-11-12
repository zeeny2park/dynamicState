/* Use-after-free fixture (b): a struct MEMBER keeps a pointer to a freed buffer and is written through.
 *
 *   g_conn     = calloc(struct conn)       (in use, reached from the global)
 *   g_conn->rx = calloc(struct buffer)     (96 bytes -> chunk 112), then free(g_conn->rx) - member not cleared
 *   every 20 ms: g_conn->rx->used += 1     (offset 24, beyond the tcache metadata)
 *
 * The dangling pointer is only reachable through the typed graph: g_conn -> struct conn .rx.
 * No malloc/free after READY.  Prints: UAF g_conn->rx <freed user addr> 112, then READY.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct buffer {
    char *base;
    long cap;
    long rd;
    long used;
    char inline_data[64];
};

struct conn {
    int fd;
    int state;
    struct buffer *rx;
    struct buffer *tx;
};

struct conn *g_conn;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    g_conn = calloc(1, sizeof *g_conn);
    g_conn->fd = 5;
    g_conn->rx = calloc(1, sizeof(struct buffer));
    g_conn->tx = calloc(1, sizeof(struct buffer));
    g_conn->rx->cap = 64;
    printf("UAF g_conn->rx %p 112\n", (void *)g_conn->rx);
    free(g_conn->rx);                     /* the bug: g_conn->rx is not cleared */
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 20 * 1000 * 1000};
    for (;;) {
        g_conn->rx->used += 1;            /* use after free through the member */
        g_conn->tx->used += 1;            /* legitimate */
        nanosleep(&ts, NULL);
    }
}
