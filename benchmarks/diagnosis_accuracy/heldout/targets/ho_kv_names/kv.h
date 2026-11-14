#ifndef KV_H
#define KV_H
#include <string.h>

#define KV_NAME_CAP 16
#define KV_SET_NAME(e, s) strcpy((e)->name, (s))

struct kv {
    int id;
    char *name;
    long value;
};

extern struct kv *kv_slots[8];

struct kv *kv_create(int id, const char *name);
void kv_rename(struct kv *e, const char *name);
#endif
