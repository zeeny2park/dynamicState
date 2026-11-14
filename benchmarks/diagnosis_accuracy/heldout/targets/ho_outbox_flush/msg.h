#ifndef MSG_H
#define MSG_H

struct msg {
    unsigned seq;
    unsigned flags;
    char text[56];
};

#define OUTBOX_LEN 4

extern struct msg *outbox[OUTBOX_LEN];
extern unsigned outbox_n;

struct msg *msg_alloc(unsigned seq);
void msg_done(struct msg *m);
void outbox_flush(void);
#endif
