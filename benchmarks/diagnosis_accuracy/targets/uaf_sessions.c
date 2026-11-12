#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct sess {
    int fd;
    int hits;
    char peer[40];
    long bytes;
};

static struct sess *g_sessions[4];

static void sess_close(int i)
{
    free(g_sessions[i]);
}

int main(void)
{
    for (int i = 0; i < 4; i++) {
        g_sessions[i] = calloc(1, sizeof(struct sess));
        g_sessions[i]->fd = 10 + i;
    }
    sess_close(1);
    g_sessions[1]->bytes += 4096;
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
