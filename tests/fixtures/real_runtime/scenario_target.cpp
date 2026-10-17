#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

struct Buffer {
    uint32_t capacity;
    uint32_t used;
    uint8_t data[64];
};

struct RuntimeState {
    uint32_t sequence;
    uint32_t status;
    Buffer buffer;
    Buffer* active;
};

// Global state instance as specified by user
RuntimeState g_state;

// Guard page and pointer for S07 & S11
void* g_guard_base = nullptr;
uint8_t* g_near_guard_ptr = nullptr;

static void setup_guard() {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    void* mem = mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED) {
        g_guard_base = mem;
        uint8_t* guard_page = (uint8_t*)mem + page_size;
        mprotect(guard_page, page_size, PROT_NONE);
        g_near_guard_ptr = guard_page - 16;
    }
}

// Candidate functions for mutation and attribution testing
extern "C" void mutate_sequence(uint32_t new_seq) {
    g_state.sequence = new_seq;
}

extern "C" void mutate_status(uint32_t new_stat) {
    g_state.status = new_stat;
}

extern "C" void mutate_buffer_used(uint32_t new_used) {
    g_state.buffer.used = new_used;
}

extern "C" void access_near_guard_candidate() {
    // Negative control: does not access guard page
    if (g_near_guard_ptr) {
        volatile void* p = g_near_guard_ptr;
        (void)p;
    }
}

int main() {
    // Initial state
    g_state.sequence = 42;
    g_state.status = 1;
    g_state.buffer.capacity = 64;
    g_state.buffer.used = 10;
    memset(g_state.buffer.data, 0, sizeof(g_state.buffer.data));
    memcpy(g_state.buffer.data, "AntigravityTestBufferData", 25);
    g_state.active = &g_state.buffer;
    setup_guard();

    // Signal READY with ground-truth oracle addresses
    printf("READY pid=%d g_state=%p sequence=%p status=%p buffer=%p buffer_used=%p active=%p guard=%p near_guard=%p\n",
           getpid(),
           (void*)&g_state,
           (void*)&g_state.sequence,
           (void*)&g_state.status,
           (void*)&g_state.buffer,
           (void*)&g_state.buffer.used,
           (void*)&g_state.active,
           g_guard_base,
           (void*)g_near_guard_ptr);
    fflush(stdout);

    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        if (strcmp(line, "QUIT") == 0 || strcmp(line, "STOP") == 0) {
            printf("BYE\n");
            fflush(stdout);
            break;
        } else if (strncmp(line, "SET sequence ", 13) == 0) {
            uint32_t val = (uint32_t)strtoul(line + 13, nullptr, 10);
            mutate_sequence(val);
            printf("OK sequence=%u\n", g_state.sequence);
            fflush(stdout);
        } else if (strncmp(line, "SET status ", 11) == 0) {
            uint32_t val = (uint32_t)strtoul(line + 11, nullptr, 10);
            mutate_status(val);
            printf("OK status=%u\n", g_state.status);
            fflush(stdout);
        } else if (strncmp(line, "SET buffer.used ", 16) == 0) {
            uint32_t val = (uint32_t)strtoul(line + 16, nullptr, 10);
            mutate_buffer_used(val);
            printf("OK buffer.used=%u\n", g_state.buffer.used);
            fflush(stdout);
        } else if (strncmp(line, "SET active ", 11) == 0) {
            char* target = line + 11;
            if (strcmp(target, "self") == 0) {
                g_state.active = &g_state.buffer;
            } else if (strcmp(target, "null") == 0) {
                g_state.active = nullptr;
            }
            printf("OK active=%p\n", (void*)g_state.active);
            fflush(stdout);
        } else if (strcmp(line, "ORACLE") == 0) {
            printf("ORACLE seq=%u stat=%u buf_used=%u active=%p\n",
                   g_state.sequence, g_state.status, g_state.buffer.used, (void*)g_state.active);
            fflush(stdout);
        } else {
            printf("ERR unknown command: %s\n", line);
            fflush(stdout);
        }
    }

    return 0;
}
