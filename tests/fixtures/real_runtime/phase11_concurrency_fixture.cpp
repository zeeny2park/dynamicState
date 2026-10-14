#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <unistd.h>
#include <signal.h>

struct WorkerState {
    int counter;
    int status_flags;
};

struct CompetingState {
    int counter;       // Same field name "counter" to test cross-object ambiguity
    int padding;
};

struct InactiveState {
    int unchanged_field; // Dedicated unchanged field for negative control
};

// Global roots for DWARF semantic traversal
WorkerState g_worker_state = {10, 1};
CompetingState g_competing_state = {20, 2};
InactiveState g_inactive_state = {999};

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_competing_ticks{0};
std::atomic<bool> g_competing_active{false};

// 1. Dedicated active writer function
void active_worker_state_writer(int new_counter, int new_flags) {
    g_worker_state.counter = new_counter;
    g_worker_state.status_flags = new_flags;
}

// 2. Competing writer mutating the exact same field in g_worker_state
void competing_worker_state_writer(int new_counter) {
    g_worker_state.counter = new_counter;
}

// 3. Mutator for the second object's counter (for cross-object ambiguity tests)
void mutate_competing_object_counter(int new_counter) {
    g_competing_state.counter = new_counter;
}

// 4. Inactive read-only function
int read_state_fn() {
    return g_worker_state.counter + g_inactive_state.unchanged_field;
}

// Background thread simulating active competing writes when enabled
void competing_thread_loop() {
    while (g_running.load(std::memory_order_relaxed)) {
        if (g_competing_active.load(std::memory_order_relaxed)) {
            competing_worker_state_writer(555);
            g_competing_ticks++;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void sig_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char** argv) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    std::thread comp_t(competing_thread_loop);

    // Command listener on stdin
    std::thread cmd_t([]() {
        std::string line;
        while (g_running.load(std::memory_order_relaxed) && std::getline(std::cin, line)) {
            if (line == "MUTATE_ACTIVE") {
                active_worker_state_writer(100, 5);
                std::cout << "ACTIVE_MUTATED" << std::endl;
                std::cout.flush();
            } else if (line == "MUTATE_COMPETING") {
                competing_worker_state_writer(200);
                std::cout << "COMPETING_MUTATED" << std::endl;
                std::cout.flush();
            } else if (line == "MUTATE_AMBIGUOUS_BOTH") {
                active_worker_state_writer(300, 7);
                mutate_competing_object_counter(300);
                std::cout << "AMBIGUOUS_MUTATED" << std::endl;
                std::cout.flush();
            } else if (line == "NOOP") {
                std::cout << "NOOP_DONE" << std::endl;
                std::cout.flush();
            } else if (line == "ENABLE_COMPETING_THREAD") {
                g_competing_active.store(true, std::memory_order_relaxed);
                std::cout << "COMPETING_THREAD_ENABLED" << std::endl;
                std::cout.flush();
            } else if (line == "STOP") {
                g_running.store(false, std::memory_order_relaxed);
                std::cout << "STOPPED" << std::endl;
                std::cout.flush();
                break;
            }
        }
    });
    cmd_t.detach();

    std::cout << "READY" << std::endl;
    std::cout.flush();

    while (g_running.load(std::memory_order_relaxed)) {
        usleep(1000);
    }

    comp_t.join();
    return 0;
}
