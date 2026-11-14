/* Consumer of the inbox ring: takes values as they arrive and folds them into a checksum. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include "ring.h"

static volatile long checksum;

static void consume(void)
{
    int v;
    for (;;) {
        if (ring_try_pop(&inbox, &v))
            checksum += v;
    }
}

static void *consumer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "consumer");
    consume();
    return NULL;
}

int main(void)
{
    pthread_t t;
    ring_push(&inbox, 1);
    pthread_create(&t, NULL, consumer, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
