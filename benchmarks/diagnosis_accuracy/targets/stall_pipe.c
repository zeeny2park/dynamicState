#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static int inbox[2];
static volatile long handled;

static long fetch_next(void)
{
    char c;
    if (read(inbox[0], &c, 1) == 1)
        return c;
    return -1;
}

static void *worker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "worker");
    for (;;) {
        fetch_next();
        handled++;
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pipe(inbox);
    pthread_create(&t, NULL, worker, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
