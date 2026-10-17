#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdint>

// Phase 25 Dedicated Real-Runtime Guard & Pool Fixture
// Models a structured memory pool with an adjacent PROT_NONE guard page.

struct BufferPool {
    uint8_t buffer[4096];
    uint32_t capacity;
    uint32_t active_bytes;
};

struct GuardTestState {
    BufferPool pool;
    uint8_t* safe_ptr;
    uint8_t* near_ptr;           // Proximity negative control (within threshold of guard page, but valid buffer memory)
    uint32_t mutation_counter;
    uint32_t status_flags;
    uint8_t* guard_page_addr;    // PROT_NONE guard page immediately following pool
};

// Global roots for DWARF semantic traversal and address mapping
GuardTestState g_guard_state;
std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_heartbeat{0};
volatile uint32_t g_verified_write_count{0};

// Function: advance safe mutation
void mutate_safe_buffer(uint32_t count, uint32_t flags) {
    g_guard_state.mutation_counter = count;
    g_guard_state.status_flags = flags;
    if (g_guard_state.safe_ptr) {
        *g_guard_state.safe_ptr = static_cast<uint8_t>(count & 0xFF);
    }
}

// Function: move near pointer close to guard boundary (negative control: proximity without access)
void adjust_near_pointer_offset(int offset_from_guard) {
    if (g_guard_state.guard_page_addr) {
        g_guard_state.near_ptr = g_guard_state.guard_page_addr + offset_from_guard;
    }
}

// Function: independent observable write tracer (for testing authenticated causal validation)
void independently_verified_boundary_write(uint8_t val) {
    if (g_guard_state.near_ptr && g_guard_state.near_ptr < g_guard_state.guard_page_addr) {
        *g_guard_state.near_ptr = val;
        g_verified_write_count++;
    }
}

// Function: read state (diagnostic)
uint32_t read_guard_status() {
    return g_guard_state.mutation_counter + g_guard_state.status_flags;
}

static void sigterm_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char* argv[]) {
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    // Allocate 2 pages: page 0 is buffer pool, page 1 is PROT_NONE guard page
    size_t page_sz = sysconf(_SC_PAGESIZE);
    void* mem = mmap(nullptr, page_sz * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        std::cerr << "mmap failed\n";
        return 1;
    }

    uint8_t* pool_page = static_cast<uint8_t*>(mem);
    uint8_t* guard_page = pool_page + page_sz;

    // Protect second page with PROT_NONE
    if (mprotect(guard_page, page_sz, PROT_NONE) != 0) {
        std::cerr << "mprotect PROT_NONE failed\n";
        return 1;
    }

    g_guard_state.pool.capacity = static_cast<uint32_t>(page_sz);
    g_guard_state.pool.active_bytes = 128;
    g_guard_state.safe_ptr = pool_page + 64;
    g_guard_state.near_ptr = guard_page - 16; // 16 bytes before guard page (within 64B threshold)
    g_guard_state.guard_page_addr = guard_page;
    g_guard_state.mutation_counter = 1;
    g_guard_state.status_flags = 0x10;

    std::cout << "READY PID=" << getpid()
              << " POOL=" << static_cast<void*>(pool_page)
              << " GUARD=" << static_cast<void*>(guard_page)
              << std::endl;
    std::cout.flush();

    while (g_running.load(std::memory_order_relaxed)) {
        mutate_safe_buffer(g_guard_state.mutation_counter + 1, 0x10);
        g_heartbeat++;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    mprotect(guard_page, page_sz, PROT_READ | PROT_WRITE);
    munmap(mem, page_sz * 2);
    return 0;
}
