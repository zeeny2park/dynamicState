/* Idle server: main thread waits for connections that have not arrived yet. */
#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

static int lsn[2];

static void *acceptor(void *arg)
{
    struct pollfd p = { .fd = lsn[0], .events = POLLIN };
    (void)arg;
    pthread_setname_np(pthread_self(), "acceptor");
    for (;;)
        poll(&p, 1, -1);
    return NULL;
}

int main(void)
{
    pthread_t t;
    pipe(lsn);
    pthread_create(&t, NULL, acceptor, NULL);
    usleep(300000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
