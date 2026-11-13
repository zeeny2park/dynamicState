#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

#define MAX_SPAWNED 400

static void *idle_worker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "conn_worker");
    for (;;)
        pause();
    return NULL;
}

static void *spawner(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "acceptor");
    for (int n = 0; n < MAX_SPAWNED; n++) {
        pthread_t t;
        if (pthread_create(&t, NULL, idle_worker, NULL) != 0)
            break;
        usleep(100000);
    }
    for (;;)
        pause();
    return NULL;
}

int main(void)
{
    pthread_t s;
    pthread_create(&s, NULL, spawner, NULL);
    usleep(1500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
