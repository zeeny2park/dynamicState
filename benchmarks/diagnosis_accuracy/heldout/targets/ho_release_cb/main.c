#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include "buf.h"

struct buf *pending;
struct buf *spare;

static void finish_pending(void)
{
    buf_put(pending);
    pending->len += 64;
}

int main(void)
{
    pending = buf_new();
    spare = buf_new();
    memcpy(pending->data, "payload", 8);
    pending->len = 8;
    finish_pending();
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
