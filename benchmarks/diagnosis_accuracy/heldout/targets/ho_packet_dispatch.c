/* Packet receive path: each packet is decoded into a fresh buffer and handed to the handler of its kind. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define NEW(T) ((T *)calloc(1, sizeof(T)))

struct packet {
    int kind;
    unsigned len;
    char body[600];
};

typedef int (*handler_fn)(struct packet *);

handler_fn handlers[2];
volatile unsigned long handled;
volatile unsigned received;

static int on_ping(struct packet *p)
{
    handled += p->len;
    return 1;
}

static int on_data(struct packet *p)
{
    handled += (unsigned char)p->body[p->len % sizeof p->body];
    return 0;
}

static void dispatch(int kind, unsigned len)
{
    struct packet *p = NEW(struct packet);
    if (!p)
        return;
    p->kind = kind;
    p->len = len;
    memset(p->body, 'p', sizeof p->body);
    if (handlers[kind & 1](p) == 0)
        return;
    free(p);
}

static void *rx_loop(void *arg)
{
    (void)arg;
    prctl(PR_SET_NAME, "rx", 0, 0, 0);
    for (unsigned n = 0;; n++) {
        dispatch((int)(n & 1), n);
        received = n + 1;
        usleep(250);
        /* FIXTURE_CAP: data packets (every 2nd) ~1.2 MiB/s; stop at ~180 MiB, stay alive. */
        if (n >= 600000u)
            for (;;)
                pause();
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    handlers[0] = on_ping;
    handlers[1] = on_data;
    pthread_create(&t, NULL, rx_loop, NULL);
    while (received < 6000)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
