#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

// Heap object
struct Session {
    int retry;
    int status;
};

// Global semantic state
struct RuntimeState {
    int counter;
    int mode;       // 1: NORMAL, 2: HIGH, 3: RESET
    int state;
    bool flag;
};

// Global shared state
RuntimeState g_state = {10, 1, 1, false};
Session* g_session = nullptr;

std::atomic<bool> g_running{true};
std::mutex g_worker_mutex;
std::condition_variable g_worker_cv;
bool g_worker_ready[3] = {false, false, false};
bool g_worker3_exit = false;

// Thread-local storage variables for TLS verification across threads
thread_local int t_thread_id = 0;
thread_local int t_worker_state = 0;
thread_local int t_worker_counter = 0;

static void sigterm_handler(int) {
    g_running.store(false);
    g_worker_cv.notify_all();
}

// Predefined observation breakpoint where GDB stops
__attribute__((noinline)) void observation_checkpoint() {
    asm volatile("" ::: "memory");
}

void worker_func(int id) {
    t_thread_id = id;
    t_worker_state = id * 10;
    t_worker_counter = id * 100 + id; // e.g. 101, 202, 303

    // Signal initialization to main thread and wait deterministically
    {
        std::unique_lock<std::mutex> lock(g_worker_mutex);
        if (id >= 1 && id <= 3) {
            g_worker_ready[id - 1] = true;
        }
        g_worker_cv.notify_all();
        g_worker_cv.wait(lock, [&]() {
            if (!g_running.load()) return true;
            if (id == 3 && g_worker3_exit) return true;
            return false;
        });
    }
}

int main(int argc, char** argv) {
    std::signal(SIGTERM, sigterm_handler);
    std::signal(SIGINT, sigterm_handler);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    // Main thread TLS and heap allocation
    t_thread_id = 100;
    t_worker_state = 0;
    t_worker_counter = 0;
    g_session = new Session{2, 1};

    printf("[sample_multithread] Spawning 3 deterministic worker threads...\n");

    std::thread w1(worker_func, 1);
    std::thread w2(worker_func, 2);
    std::thread w3(worker_func, 3);

    // Wait until all 3 worker threads are initialized and at deterministic wait barrier
    {
        std::unique_lock<std::mutex> lock(g_worker_mutex);
        g_worker_cv.wait(lock, [&]() {
            return g_worker_ready[0] && g_worker_ready[1] && g_worker_ready[2];
        });
    }

    // INITIAL OBSERVATION POINT (THREADS = 4)
    observation_checkpoint();

    // 1. Crash branch isolation trigger
    if (g_state.state == 139) {
        printf("[sample_multithread] Deliberate SIGSEGV crash triggered\n");
        *(volatile int*)0 = 42;
    }

    // 2. Timeout branch isolation trigger
    if (g_state.state == 255) {
        printf("[sample_multithread] Deliberate infinite loop triggered\n");
        while (g_state.state == 255 && g_running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // 3. Thread lifecycle: dynamic thread creation trigger (Case A)
    std::thread* w4 = nullptr;
    if (g_state.state == 500) {
        printf("[sample_multithread] Spawning 4th worker thread (threads=5)...\n");
        w4 = new std::thread(worker_func, 4);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        observation_checkpoint();
    }

    // 4. Thread lifecycle: worker termination trigger (Case B)
    if (g_state.state == 600) {
        printf("[sample_multithread] Terminating worker 3 (threads=3)...\n");
        {
            std::lock_guard<std::mutex> lock(g_worker_mutex);
            g_worker3_exit = true;
            g_worker_cv.notify_all();
        }
        if (w3.joinable()) {
            w3.join();
        }
        observation_checkpoint();
    }

    // Normal state machine progression
    if (g_state.counter > 20) {
        g_state.state = 2; // HIGH
        g_state.mode = 2;
        g_state.flag = true;
        if (g_session) g_session->status = 2;
    } else if (g_state.counter <= 0) {
        g_state.state = 0; // RESET
        g_state.mode = 3;
        g_state.flag = false;
        if (g_session) g_session->status = 0;
    } else {
        g_state.state = 1; // NORMAL
        g_state.mode = 1;
    }

    // POST-EXECUTION OBSERVATION POINT
    observation_checkpoint();

    // Clean shutdown
    {
        std::lock_guard<std::mutex> lock(g_worker_mutex);
        g_running.store(false);
        g_worker_cv.notify_all();
    }

    if (w1.joinable()) w1.join();
    if (w2.joinable()) w2.join();
    if (w3.joinable()) w3.join();
    if (w4) {
        if (w4->joinable()) w4->join();
        delete w4;
    }
    if (g_session) {
        delete g_session;
        g_session = nullptr;
    }

    printf("[sample_multithread] Finished.\n");
    return 0;
}
