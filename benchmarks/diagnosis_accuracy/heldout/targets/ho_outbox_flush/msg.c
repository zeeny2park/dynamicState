/* Outgoing messages: queued in a small outbox, sent ones are released by the sender. */
#include <stdlib.h>
#include <string.h>
#include "msg.h"

struct msg *outbox[OUTBOX_LEN];
unsigned outbox_n;

struct msg *msg_alloc(unsigned seq)
{
    struct msg *m = malloc(sizeof *m);
    m->seq = seq;
    m->flags = 0;
    memset(m->text, 'm', sizeof m->text);
    return m;
}

void msg_done(struct msg *m)
{
    m->flags |= 1u;
    free(m);
}

void outbox_flush(void)
{
    for (unsigned i = 0; i < outbox_n; i++)
        free(outbox[i]);
    outbox_n = 0;
}
