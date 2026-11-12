/* Lazily initialised subsystems: their global pointers are intentionally NULL until first use. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

struct conf { int level; };
struct conn { int fd; };

struct conf *cfg;
struct conn *upstream;
char *scratch;
void (*on_event)(int);
static int idle_ticks;

static void *ticker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "ticker");
    for (;;) {
        usleep(50000);
        idle_ticks++;
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, ticker, NULL);
    while (idle_ticks < 5)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
