/* Byte ring buffer; the producer copies a whole message in one go. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ring {
    unsigned char *buf;
    size_t cap, head, tail;
};

static struct ring rb;
static unsigned char *aux;

static void rb_init(struct ring *r, size_t cap)
{
    r->buf = malloc(cap);
    r->cap = cap;
    r->head = r->tail = 0;
}

static size_t rb_put(struct ring *r, const unsigned char *src, size_t len)
{
    memcpy(r->buf + r->head, src, len);
    r->head = (r->head + len) % r->cap;
    return len;
}

int main(void)
{
    unsigned char msg[96];
    memset(msg, 'm', sizeof msg);
    rb_init(&rb, 64);
    aux = malloc(64);
    memset(aux, 0, 64);
    rb_put(&rb, msg, sizeof msg);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
