#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static volatile int pending = 7;

static void flush_remote(void)
{
    sleep(86400);
    pending = 0;
}

static void *syncer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "syncer");
    flush_remote();
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, syncer, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
