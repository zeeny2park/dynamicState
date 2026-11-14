/* Single-producer single-consumer ring; pop never waits. */
#include "ring.h"

struct ring inbox;

int ring_try_pop(struct ring *r, int *out)
{
    if (r->tail == r->head)
        return 0;
    *out = r->slot[r->tail % RING_SLOTS];
    r->tail++;
    return 1;
}

void ring_push(struct ring *r, int v)
{
    r->slot[r->head % RING_SLOTS] = v;
    r->head++;
}
