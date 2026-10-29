#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct BufferSlot {
    int32_t in_use;
    int32_t size;
    int32_t owner_tid;
    int32_t seq;
    char* data_ptr;
};

struct MemPool {
    int32_t total_buffers;
    int32_t active_buffers;
    BufferSlot buffers[32];
};

MemPool g_pool_storage;
MemPool* gpMem = &g_pool_storage;

int main() {
    memset(&g_pool_storage, 0, sizeof(g_pool_storage));
    gpMem->total_buffers = 32;
    gpMem->active_buffers = 10;

    // Allocate 10 specific slots: 0, 1, 4, 5, 8, 12, 13, 20, 24, 31
    int allocated[] = {0, 1, 4, 5, 8, 12, 13, 20, 24, 31};
    for (int i = 0; i < 10; ++i) {
        int idx = allocated[i];
        gpMem->buffers[idx].in_use = 1;
        gpMem->buffers[idx].size = (idx + 1) * 64;
        gpMem->buffers[idx].seq = 1000 + idx;
        gpMem->buffers[idx].data_ptr = (char*)malloc(128);
    }

    printf("=== Memory Pool Demo Running (PID: %d) ===\n", getpid());
    fflush(stdout);

    while (true) {
        usleep(50000);
    }
    return 0;
}
