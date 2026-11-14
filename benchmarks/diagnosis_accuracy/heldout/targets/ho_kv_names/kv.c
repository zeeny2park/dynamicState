/* Small key/value slots; each slot owns a short heap-allocated name. */
#include <stdlib.h>
#include "kv.h"

struct kv *kv_slots[8];

struct kv *kv_create(int id, const char *name)
{
    struct kv *e = calloc(1, sizeof *e);
    e->id = id;
    e->name = malloc(KV_NAME_CAP);
    KV_SET_NAME(e, name);
    return e;
}

void kv_rename(struct kv *e, const char *name)
{
    KV_SET_NAME(e, name);
    e->value++;
}
