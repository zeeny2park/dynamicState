#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

struct RuntimeState {
    int counter;
    int state;
    bool flag;
};

// Global shared state
RuntimeState g_state = {10, 1, false};
std::atomic<bool> g_running{true};
std::atomic<int> g_worker_ticks{0};

// Thread-local storage state to verify TLS isolation
thread_local int t_thread_id = 0;

static void sigterm_handler(int) {
    g_running.store(false);
}

// Observation point where GDB sets breakpoint
__attribute__((noinline)) void observation_checkpoint() {
    asm volatile("" ::: "memory");
}

void worker_func(int id) {
    t_thread_id = id;
    while (g_running.load()) {
        g_worker_ticks.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

int main(int argc, char** argv) {
    std::signal(SIGTERM, sigterm_handler);
    std::signal(SIGINT, sigterm_handler);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    t_thread_id = 100; // Main thread TLS

    printf("[sample_multithread] Starting with 3 worker threads...\n");

    std::thread w1(worker_func, 1);
    std::thread w2(worker_func, 2);
    std::thread w3(worker_func, 3);

    // Let workers spin up
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Reached observation point
    observation_checkpoint();

    // Check for crash trigger
    if (g_state.state == 139) {
        *(volatile int*)0 = 42; // Deliberate crash
    }

    // Check for timeout trigger
    if (g_state.state == 255) {
        while (g_state.state == 255 && g_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // Normal state machine progression
    if (g_state.counter > 20) {
        g_state.state = 2; // HIGH
        g_state.flag = true;
    } else if (g_state.counter <= 0) {
        g_state.state = 0; // RESET
        g_state.flag = false;
    } else {
        g_state.state = 1; // NORMAL
    }

    // Post-execution observation point
    observation_checkpoint();

    g_running.store(false);
    w1.join();
    w2.join();
    w3.join();

    printf("[sample_multithread] Finished. Final state: counter=%d state=%d flag=%d\n",
           g_state.counter, g_state.state, g_state.flag ? 1 : 0);
    return 0;
}
