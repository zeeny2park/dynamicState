/* Reference-counted buffers; the last put hands the buffer to its release callback. */
#include <stdlib.h>
#include <string.h>
#include "buf.h"

static void heap_release(struct buf *b)
{
    free(b);
}

struct buf_ops heap_ops = { heap_release };

struct buf *buf_new(void)
{
    struct buf *b = calloc(1, sizeof *b);
    b->ops = &heap_ops;
    b->refs = 1;
    return b;
}

void buf_put(struct buf *b)
{
    if (--b->refs == 0)
        b->ops->release(b);
}
