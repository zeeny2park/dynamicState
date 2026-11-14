#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include "msg.h"

static struct msg *batch[7];

int main(void)
{
    struct msg *first = msg_alloc(1);
    struct msg *second = msg_alloc(2);
    outbox[outbox_n++] = first;
    for (int i = 0; i < 7; i++)
        batch[i] = msg_alloc(100 + i);
    for (int i = 0; i < 7; i++)
        msg_done(batch[i]);
    msg_done(first);
    msg_done(second);
    outbox_flush();
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
