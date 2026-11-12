/* Busy request loop: two threads do real work and publish progress; memory stays flat. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

static volatile uint64_t handled[2];
static volatile uint32_t digest[2];

static uint32_t crunch(uint32_t seed)
{
    uint32_t h = seed;
    for (int i = 0; i < 20000; i++)
        h = h * 2654435761u + (uint32_t)i;
    return h;
}

static void *serve_loop(void *arg)
{
    int me = (int)(intptr_t)arg;
    pthread_setname_np(pthread_self(), me ? "serve1" : "serve0");
    for (;;) {
        digest[me] = crunch(digest[me] + (uint32_t)handled[me]);
        handled[me]++;
        usleep(2000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[2];
    for (intptr_t i = 0; i < 2; i++)
        pthread_create(&t[i], NULL, serve_loop, (void *)i);
    while (handled[0] < 50 || handled[1] < 50)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
