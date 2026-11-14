#ifndef RING_H
#define RING_H
#define RING_SLOTS 64

struct ring {
    volatile unsigned head;
    volatile unsigned tail;
    int slot[RING_SLOTS];
};

extern struct ring inbox;
int ring_try_pop(struct ring *r, int *out);
void ring_push(struct ring *r, int v);
#endif
