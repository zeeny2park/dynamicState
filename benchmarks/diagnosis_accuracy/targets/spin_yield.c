#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

static volatile int ev;

static void await_event(void)
{
    while (ev == 0)
        sched_yield();
}

static void *waiter(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "waiter");
    await_event();
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, waiter, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
