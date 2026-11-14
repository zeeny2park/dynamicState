// Expert Diagnostic Scenario Test Program (Phase 2.1 & 2.1.1)
// Supports deterministic simulation of positive faults, healthy negative states,
// borderline ambiguous metrics, and stripped/insufficient evidence configurations.

#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

struct WorkerNode {
    uint32_t magic;           // 0xCAFEBABE for valid, 0xDEADBEEF for corrupted
    uint32_t state;           // 0: IDLE, 1: ACTIVE, 2: PAUSED, 999: INVALID
    uint64_t counter;
    char name[32];
    void* payload_ptr;
};

// Global state variables
volatile int g_heartbeat = 0;
volatile int g_worker_state = 1;
volatile uint64_t g_transaction_count = 100;
volatile uint64_t g_alloc_count = 0;
volatile uint64_t g_free_count = 0;
volatile uint32_t g_buffer_capacity = 1024;
volatile uint32_t g_buffer_length = 64;

WorkerNode g_active_node = {0xCAFEBABE, 1, 42, "WorkerNode_01", nullptr};
// Sibling nodes: their agreeing magic (0xCAFEBABE) is the expected value a corrupted node is judged against.
// A magic value alone (0xDEADBEEF) is not evidence of corruption - it is often a program's VALID magic.
WorkerNode g_worker_pool[4] = {{0xCAFEBABE, 1, 1, "pool_0", nullptr}, {0xCAFEBABE, 1, 2, "pool_1", nullptr},
                               {0xCAFEBABE, 1, 3, "pool_2", nullptr}, {0xCAFEBABE, 1, 4, "pool_3", nullptr}};

std::mutex g_mutex_a;
std::mutex g_mutex_b;
std::vector<void*> g_leak_pool;

void worker_healthy_loop() {
    while (true) {
        g_heartbeat++;
        g_transaction_count += 2;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void trigger_memory_corruption() {
    g_active_node.magic = 0xDEADBEEF; // Corrupt magic
    g_worker_pool[2].magic = 0xDEADBEEF; // the same overwrite hits a pooled node: it now disagrees with its siblings
    g_active_node.payload_ptr = (void*)0x40; // Low-memory invalid address (within NULL page guard)
}

void trigger_memory_leak() {
    for (int i = 0; i < 200; ++i) {
        void* p = malloc(1024 * 64); // 64KB per slot
        if (p) {
            memset(p, 0xAA, 1024 * 64);
            g_leak_pool.push_back(p);
        }
    }
    g_alloc_count += 200;
    // Spawn periodic background allocator for temporal growth
    std::thread([]() {
        for (int i = 0; i < 50; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            void* p = malloc(1024 * 128);
            if (p) {
                memset(p, 0xBB, 1024 * 128);
                g_leak_pool.push_back(p);
            }
            g_alloc_count++;
        }
    }).detach();
}

void trigger_alloc_imbalance() {
    g_alloc_count = 1250;
    g_free_count = 42;
    for (int i = 0; i < 150; ++i) {
        void* p = malloc(1024 * 32);
        if (p) g_leak_pool.push_back(p);
    }
    // The imbalance keeps growing: allocations continue, frees do not (a static ratio alone is not a leak).
    // FIXTURE_CAP: 1500 x 4 KiB over ~30 s.
    std::thread([]() {
        for (int i = 0; i < 1500; ++i) {
            void* p = malloc(4096);
            if (p) { memset(p, 0x5C, 4096); g_leak_pool.push_back(p); }
            g_alloc_count++;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }).detach();
}

void trigger_abnormal_state() {
    g_worker_state = 999; // Boundary violation (> 100)
    g_active_node.state = 999;
}

void trigger_field_inconsistency() {
    // Invariant violation: length cannot exceed capacity
    g_buffer_capacity = 64;
    g_buffer_length = 4096;
    g_active_node.counter = 0xFFFFFFFFFFFFFFFFULL;
}

void thread_deadlock_a() {
    std::lock_guard<std::mutex> lock_a(g_mutex_a);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::lock_guard<std::mutex> lock_b(g_mutex_b);
}

void thread_deadlock_b() {
    std::lock_guard<std::mutex> lock_b(g_mutex_b);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::lock_guard<std::mutex> lock_a(g_mutex_a);
}

void thread_blocked_holder() {
    std::lock_guard<std::mutex> lock_a(g_mutex_a);
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void thread_blocked_waiter() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::lock_guard<std::mutex> lock_a(g_mutex_a);
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "healthy";

    std::cout << "[dynamicState Test Fixture] PID: " << getpid() << " Mode: " << mode << std::endl;

    if (mode == "corrupt") {
        trigger_memory_corruption();
    } else if (mode == "leak") {
        trigger_memory_leak();
    } else if (mode == "alloc_imbalance") {
        trigger_alloc_imbalance();
    } else if (mode == "abnormal_state" || mode == "state_transition") {
        trigger_abnormal_state();
    } else if (mode == "field_inconsistency") {
        trigger_field_inconsistency();
    } else if (mode == "deadlock") {
        std::thread t1(thread_deadlock_a);
        std::thread t2(thread_deadlock_b);
        t1.detach();
        t2.detach();
    } else if (mode == "blocked_no_deadlock") {
        std::thread t1(thread_blocked_holder);
        std::thread t2(thread_blocked_waiter);
        t1.detach();
        t2.detach();
    }

    worker_healthy_loop();
    return 0;
}
