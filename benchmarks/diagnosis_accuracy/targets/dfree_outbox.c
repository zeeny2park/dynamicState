/* Outgoing message queue; an oversized message is dropped on the send path and retired again later. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct msg {
    struct msg *next;
    int len;
    char data[40];
};

static struct msg *outbox;
static struct msg *last_sent;

static struct msg *msg_new(int len)
{
    struct msg *m = calloc(1, sizeof *m);
    m->len = len;
    return m;
}

static void outbox_push(int len)
{
    struct msg *m = msg_new(len);
    m->next = outbox;
    outbox = m;
}

static void outbox_flush(void)
{
    while (outbox) {
        struct msg *m = outbox;
        outbox = m->next;
        free(m);
    }
}

static void send_one(struct msg *m)
{
    last_sent = m;
    if (m->len > (int)sizeof m->data - 8)
        free(m);
}

static void retire(struct msg *m)
{
    free(m);
}

int main(void)
{
    for (int i = 0; i < 9; i++)
        outbox_push(16);
    struct msg *a = msg_new(40);
    struct msg *b = msg_new(8);
    outbox_flush();
    send_one(a);
    retire(b);
    retire(a);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
