/* Event intake keeps every record on a singly linked list. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

struct ent {
    struct ent *next;
    unsigned id;
    char body[1000];
};

static struct ent *reg_head;
static volatile unsigned reg_n;

static void *intake(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "intake");
    for (;;) {
        struct ent *e = calloc(1, sizeof *e);
        if (!e)
            break;
        e->id = reg_n;
        e->next = reg_head;
        reg_head = e;
        reg_n++;
        usleep(500);
        /* FIXTURE_CAP: ~1.8 MiB/s measured; stop at ~500 MiB (~5 min), stay alive. */
        if (reg_n >= 500000u)
            for (;;)
                pause();
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, intake, NULL);
    while (reg_n < 2000)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
