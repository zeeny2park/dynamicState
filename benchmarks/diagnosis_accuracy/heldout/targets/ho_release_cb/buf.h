#ifndef BUF_H
#define BUF_H
#include <stddef.h>

struct buf;

struct buf_ops {
    void (*release)(struct buf *b);
};

struct buf {
    const struct buf_ops *ops;
    int refs;
    size_t len;
    char data[200];
};

extern struct buf_ops heap_ops;

struct buf *buf_new(void);
void buf_put(struct buf *b);
#endif
