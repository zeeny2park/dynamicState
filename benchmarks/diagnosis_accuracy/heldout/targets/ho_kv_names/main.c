#define _GNU_SOURCE
#include <unistd.h>
#include "kv.h"

int main(void)
{
    for (int i = 0; i < 4; i++)
        kv_slots[i] = kv_create(i, "slot");
    kv_rename(kv_slots[1], "replica-west-2.internal.example");
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
