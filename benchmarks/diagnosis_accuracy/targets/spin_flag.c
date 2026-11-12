#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static volatile int go;
static volatile unsigned long laps;

static void *poll_loop(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "poller");
    while (!go)
        laps++;
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, poll_loop, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
