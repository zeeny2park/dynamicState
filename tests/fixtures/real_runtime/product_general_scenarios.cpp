/**
 * Phase 2.1.2 — Product-General Real Runtime C++ Investigation Scenarios
 *
 * Provides diverse, realistic C++ domain structures completely independent
 * of earlier test fixture naming conventions:
 * - NetworkBufferPool, SessionRecord, OrderBookCache, WorkerGroup
 * - Global/static variables: g_pkt_pool, g_active_sessions, g_rx_buffer, etc.
 * - Simulates scenarios A through P for rigorous product-general verification.
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstdlib>
#include <unistd.h>

struct NetworkBuffer {
    uint32_t magic_header;
    uint32_t system_state;
    uint32_t max_capacity;
    uint32_t payload_length;
    char buffer_name[32];
    void* payload_ptr;
};

struct SessionRecord {
    uint64_t session_id;
    uint32_t flags;
    uint32_t tenant_id;
    void* session_context;
};

// Global symbols with production-like names
volatile int g_service_heartbeat = 1;
volatile int g_cluster_state = 2; // Normal active state
volatile uint64_t g_rx_packets = 1000;
volatile uint64_t g_tx_packets = 1000;
volatile uint64_t g_alloc_ops = 0;
volatile uint64_t g_release_ops = 0;

NetworkBuffer g_rx_buffer = {
    0x504B5431, // "PKT1"
    2,          // Normal state
    2048,       // Capacity
    128,        // Length
    "RxBuffer_Main",
    nullptr     // Clean idle NULL pointer
};

std::mutex g_flow_ingress_mutex;
std::mutex g_flow_egress_mutex;

std::vector<void*> g_retained_telemetry_records;

void run_healthy_service() {
    while (true) {
        g_service_heartbeat++;
        g_rx_packets += 5;
        g_tx_packets += 5;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void trigger_memory_corruption() {
    g_rx_buffer.magic_header = 0xDEADBEEF;
    g_rx_buffer.payload_ptr = (void*)0x80; // Low-memory invalid pointer
}

void trigger_sustained_accumulation() {
    for (int i = 0; i < 250; ++i) {
        void* mem = malloc(1024 * 32);
        if (mem) {
            memset(mem, 0x5A, 1024 * 32);
            g_retained_telemetry_records.push_back(mem);
        }
    }
    g_alloc_ops += 250;
    // Periodic background leak
    std::thread([]() {
        for (int i = 0; i < 100; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            void* mem = malloc(1024 * 64);
            if (mem) {
                memset(mem, 0x5B, 1024 * 64);
                g_retained_telemetry_records.push_back(mem);
            }
            g_alloc_ops++;
        }
    }).detach();
}

void trigger_alloc_imbalance() {
    g_alloc_ops = 2400;
    g_release_ops = 10;
    for (int i = 0; i < 120; ++i) {
        void* mem = malloc(1024 * 16);
        if (mem) g_retained_telemetry_records.push_back(mem);
    }
    // The imbalance keeps growing: allocations continue, releases do not (a static ratio alone is not a leak).
    // FIXTURE_CAP: 1500 x 4 KiB over ~30 s.
    std::thread([]() {
        for (int i = 0; i < 1500; ++i) {
            void* mem = malloc(4096);
            if (mem) { memset(mem, 0x5D, 4096); g_retained_telemetry_records.push_back(mem); }
            g_alloc_ops++;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }).detach();
}

void trigger_field_invariant_violation() {
    // Invariant: payload_length cannot exceed max_capacity
    g_rx_buffer.max_capacity = 256;
    g_rx_buffer.payload_length = 8192;
    g_cluster_state = 999; // Boundary violation (> 100)
}

void deadlock_ingress() {
    std::lock_guard<std::mutex> l1(g_flow_ingress_mutex);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::lock_guard<std::mutex> l2(g_flow_egress_mutex);
}

void deadlock_egress() {
    std::lock_guard<std::mutex> l1(g_flow_egress_mutex);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::lock_guard<std::mutex> l2(g_flow_ingress_mutex);
}

void lock_contention_holder() {
    while (true) {
        g_flow_ingress_mutex.lock();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        g_flow_ingress_mutex.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void lock_contention_waiter() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    std::lock_guard<std::mutex> lk(g_flow_ingress_mutex);
}

int main(int argc, char** argv) {
    std::string mode = (argc > 1) ? argv[1] : "healthy";
    std::cout << "[ProductGeneral Fixture] PID: " << getpid() << " Mode: " << mode << std::endl;

    if (mode == "corrupt") {
        trigger_memory_corruption();
    } else if (mode == "leak") {
        trigger_sustained_accumulation();
    } else if (mode == "alloc_imbalance") {
        trigger_alloc_imbalance();
    } else if (mode == "invariant_violation") {
        trigger_field_invariant_violation();
    } else if (mode == "deadlock") {
        std::thread t1(deadlock_ingress);
        std::thread t2(deadlock_egress);
        t1.detach();
        t2.detach();
    } else if (mode == "contention") {
        std::thread t1(lock_contention_holder);
        std::thread t2(lock_contention_waiter);
        t1.detach();
        t2.detach();
    }

    // Keep process alive for zero-stop investigation
    run_healthy_service();
    return 0;
}
