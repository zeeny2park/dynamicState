// Phase 2.1.8 — Realistic C/C++ Runtime Diagnostic Validation Targets (Parts C1, C2, C3)
// Compiled with -g -O0 -pthread (and stripped variant with -s) for live process inspection.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern "C" {

// Global telemetry and diagnostic symbols inspectable via DWARF / ELF symtab + process_vm_readv
volatile uint64_t g_scenario_id = 0;
volatile uint64_t g_epoch_counter = 0;
volatile uint64_t g_alloc_count = 0;
volatile uint64_t g_free_count = 0;
volatile uint64_t g_active_bytes = 0;
volatile uint64_t g_container_size = 0;
volatile uint64_t g_container_capacity = 0;
volatile uint64_t g_canary_word = 0xDEADBEEFCAFEBABEULL;
volatile uint64_t g_stack_canary = 0xBADC0FFEE0DDF00DULL;
volatile uint64_t g_dangling_ptr = 0;
volatile uint64_t g_invalid_free_ptr = 0;
volatile uint64_t g_wild_ptr = 0;
volatile uint64_t g_double_free_count = 0;
volatile uint64_t g_lock_order_inversions = 0;
volatile uint64_t g_starved_wait_iterations = 0;
volatile uint64_t g_progress_counter = 0;
volatile uint64_t g_leaked_fd_count = 0;
volatile uint64_t g_spawned_thread_count = 0;
volatile uint64_t g_static_global_var = 0x1122334455667788ULL;

struct CoupledBufferState {
    uint64_t magic;
    uint64_t capacity;
    uint64_t length;
    uint64_t canary;
    char payload[64];
};

volatile CoupledBufferState g_coupled_state = {
    0x4F4B4F4B4F4B4F4BULL, 64, 16, 0xDEADBEEFCAFEBABEULL, {0}
};

pthread_mutex_t g_mutex_a = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_mutex_b = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_mutex_c = PTHREAD_MUTEX_INITIALIZER;

} // extern "C"

static std::vector<void*> g_retained_chunks;
static std::vector<std::thread> g_bg_threads;

// C2-01: Classic 2-thread AB-BA deadlock
static void worker_abba_1(std::atomic<int>* barrier) {
    pthread_mutex_lock(&g_mutex_a);
    barrier->fetch_add(1);
    while (barrier->load() < 2) {
        usleep(1000);
    }
    pthread_mutex_lock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_b);
    pthread_mutex_unlock(&g_mutex_a);
}

static void worker_abba_2(std::atomic<int>* barrier) {
    pthread_mutex_lock(&g_mutex_b);
    barrier->fetch_add(1);
    while (barrier->load() < 2) {
        usleep(1000);
    }
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_b);
}

// C2-02: 3-thread circular wait deadlock (T1->A->B, T2->B->C, T3->C->A)
static void worker_cycle3_1(std::atomic<int>* barrier) {
    pthread_mutex_lock(&g_mutex_a);
    barrier->fetch_add(1);
    while (barrier->load() < 3) usleep(1000);
    pthread_mutex_lock(&g_mutex_b);
}

static void worker_cycle3_2(std::atomic<int>* barrier) {
    pthread_mutex_lock(&g_mutex_b);
    barrier->fetch_add(1);
    while (barrier->load() < 3) usleep(1000);
    pthread_mutex_lock(&g_mutex_c);
}

static void worker_cycle3_3(std::atomic<int>* barrier) {
    pthread_mutex_lock(&g_mutex_c);
    barrier->fetch_add(1);
    while (barrier->load() < 3) usleep(1000);
    pthread_mutex_lock(&g_mutex_a);
}

// C2-03: Heavy lock contention without cycle (T1 holds g_mutex_a, T2 blocks on g_mutex_a)
static void worker_contention_holder(std::atomic<int>* ready) {
    pthread_mutex_lock(&g_mutex_a);
    ready->store(1);
    while (true) {
        g_progress_counter++;
        usleep(50000);
    }
}

static void worker_contention_waiter(std::atomic<int>* ready) {
    while (ready->load() == 0) usleep(1000);
    pthread_mutex_lock(&g_mutex_a);
    pthread_mutex_unlock(&g_mutex_a);
}

int main(int argc, char** argv) {
    const char* mode = (argc > 1) ? argv[1] : "c3_01_healthy_steady";

    if (std::strcmp(mode, "c1_01_heap_leak") == 0) {
        g_scenario_id = 101;
        for (int i = 0; i < 16; ++i) {
            char* buf = static_cast<char*>(std::malloc(256 * 1024));
            if (buf) {
                std::memset(buf, 0x5A, 256 * 1024);
                g_retained_chunks.push_back(buf);
                g_alloc_count++;
                g_active_bytes += 256 * 1024;
            }
            g_epoch_counter++;
            usleep(10000);
        }
        while (true) {
            char* buf = static_cast<char*>(std::malloc(128 * 1024));
            if (buf) {
                std::memset(buf, 0x5A, 128 * 1024);
                g_retained_chunks.push_back(buf);
                g_alloc_count++;
                g_active_bytes += 128 * 1024;
            }
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_02_transient_warmup") == 0) {
        g_scenario_id = 102;
        // Allocate bounded cache once, then plateau
        for (int i = 0; i < 8; ++i) {
            char* buf = static_cast<char*>(std::malloc(64 * 1024));
            if (buf) {
                std::memset(buf, 0x11, 64 * 1024);
                g_retained_chunks.push_back(buf);
                g_alloc_count++;
                g_active_bytes += 64 * 1024;
            }
        }
        while (true) {
            g_epoch_counter++;
            g_progress_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_03_container_accumulation") == 0) {
        g_scenario_id = 103;
        for (int i = 0; i < 200; ++i) {
            char* item = new char[4096];
            std::memset(item, 0x33, 4096);
            g_retained_chunks.push_back(item);
            g_alloc_count++;
        }
        g_container_size = g_retained_chunks.size();
        g_container_capacity = g_retained_chunks.capacity();
        while (true) {
            char* item = new char[4096];
            std::memset(item, 0x33, 4096);
            g_retained_chunks.push_back(item);
            g_alloc_count++;
            g_container_size = g_retained_chunks.size();
            g_container_capacity = g_retained_chunks.capacity();
            g_epoch_counter++;
            usleep(25000);
        }
    } else if (std::strcmp(mode, "c1_04_arena_fragmentation") == 0) {
        g_scenario_id = 104;
        std::vector<void*> temp_chunks;
        for (int i = 0; i < 64; ++i) {
            void* p = std::malloc(32 * 1024);
            if (p) {
                std::memset(p, 0x22, 32 * 1024);
                temp_chunks.push_back(p);
                g_alloc_count++;
            }
        }
        // Free 62 of 64 chunks, leaving high-address chunk pinned so heap VMA stays expanded while live count is tiny
        for (size_t i = 0; i + 2 < temp_chunks.size(); ++i) {
            std::free(temp_chunks[i]);
            g_free_count++;
        }
        g_active_bytes = 2 * 32 * 1024;
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_05_alloc_free_imbalance") == 0) {
        g_scenario_id = 105;
        g_alloc_count = 5000;
        g_free_count = 120;
        g_active_bytes = (5000 - 120) * 1024;
        while (true) {
            g_alloc_count += 10;
            g_free_count += 1;
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_06_use_after_free") == 0) {
        g_scenario_id = 106;
        uint64_t* obj = static_cast<uint64_t*>(std::malloc(128));
        if (obj) {
            obj[0] = 0xFEEDFACECAFEBEEFULL;
            g_dangling_ptr = reinterpret_cast<uint64_t>(obj);
            // Poison and free
            obj[0] = 0xDEADDEADDEADDEADULL;
            std::free(obj);
            g_alloc_count = 1;
            g_free_count = 1;
        }
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_07_double_free") == 0) {
        g_scenario_id = 107;
        void* p = std::malloc(128);
        g_dangling_ptr = reinterpret_cast<uint64_t>(p);
        std::free(p);
        g_alloc_count = 1;
        g_free_count = 2;
        g_double_free_count = 2;
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_08_invalid_free_stack_static") == 0) {
        g_scenario_id = 108;
        uint64_t stack_local = 0xABCDEF0123456789ULL;
        g_invalid_free_ptr = reinterpret_cast<uint64_t>(&stack_local);
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_09_heap_buffer_overflow") == 0) {
        g_scenario_id = 109;
        g_canary_word = 0x4141414141414141ULL; // Overwritten canary
        g_coupled_state.canary = 0x4141414141414141ULL;
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_10_adjacent_object_corruption") == 0) {
        g_scenario_id = 110;
        g_coupled_state.magic = 0x4242424242424242ULL;
        g_coupled_state.capacity = 64;
        g_coupled_state.length = 99999; // Violates length <= capacity due to adjacent overflow
        g_coupled_state.canary = 0x4242424242424242ULL;
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_11_stack_frame_corruption") == 0) {
        g_scenario_id = 111;
        g_stack_canary = 0x5858585858585858ULL; // Clobbered stack canary
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c1_12_null_wild_pointer") == 0) {
        g_scenario_id = 112;
        g_wild_ptr = 0x0000000000000010ULL; // Invalid NULL guard page pointer
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c2_01_abba_deadlock") == 0) {
        g_scenario_id = 201;
        std::atomic<int> barrier{0};
        std::thread t1(worker_abba_1, &barrier);
        std::thread t2(worker_abba_2, &barrier);
        t1.join();
        t2.join();
    } else if (std::strcmp(mode, "c2_02_three_thread_deadlock") == 0) {
        g_scenario_id = 202;
        std::atomic<int> barrier{0};
        std::thread t1(worker_cycle3_1, &barrier);
        std::thread t2(worker_cycle3_2, &barrier);
        std::thread t3(worker_cycle3_3, &barrier);
        t1.join();
        t2.join();
        t3.join();
    } else if (std::strcmp(mode, "c2_03_heavy_contention") == 0) {
        g_scenario_id = 203;
        std::atomic<int> ready{0};
        std::thread t1(worker_contention_holder, &ready);
        std::thread t2(worker_contention_waiter, &ready);
        t1.join();
        t2.join();
    } else if (std::strcmp(mode, "c2_04_slow_progress_compute") == 0) {
        g_scenario_id = 204;
        while (true) {
            for (volatile int k = 0; k < 50000; ++k) {}
            g_progress_counter++;
            g_epoch_counter++;
            usleep(10000);
        }
    } else if (std::strcmp(mode, "c2_05_starvation") == 0) {
        g_scenario_id = 205;
        g_starved_wait_iterations = 15000;
        std::atomic<int> ready{0};
        std::thread t1(worker_contention_holder, &ready);
        std::thread t2(worker_contention_waiter, &ready);
        t1.join();
        t2.join();
    } else if (std::strcmp(mode, "c2_06_normal_sync") == 0) {
        g_scenario_id = 206;
        while (true) {
            pthread_mutex_lock(&g_mutex_a);
            g_progress_counter++;
            pthread_mutex_unlock(&g_mutex_a);
            g_epoch_counter++;
            usleep(20000);
        }
    } else if (std::strcmp(mode, "c2_07_inconsistent_lock_order") == 0) {
        g_scenario_id = 207;
        g_lock_order_inversions = 14;
        while (true) {
            g_progress_counter++;
            g_epoch_counter++;
            usleep(25000);
        }
    } else if (std::strcmp(mode, "c2_08_transient_wait") == 0) {
        g_scenario_id = 208;
        while (true) {
            g_progress_counter++;
            g_epoch_counter++;
            usleep(20000);
        }
    } else if (std::strcmp(mode, "c3_02_fd_exhaustion") == 0) {
        g_scenario_id = 302;
        for (int i = 0; i < 40; ++i) {
            int fds[2];
            if (pipe(fds) == 0) {
                g_leaked_fd_count += 2;
            }
        }
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else if (std::strcmp(mode, "c3_03_thread_proliferation") == 0) {
        g_scenario_id = 303;
        for (int i = 0; i < 12; ++i) {
            g_bg_threads.emplace_back([]() {
                while (true) {
                    usleep(100000);
                }
            });
            g_spawned_thread_count++;
        }
        while (true) {
            g_epoch_counter++;
            usleep(30000);
        }
    } else {
        // c3_01_healthy_steady and default clean runtime
        g_scenario_id = 301;
        while (true) {
            g_progress_counter++;
            g_epoch_counter++;
            usleep(25000);
        }
    }
    return 0;
}
