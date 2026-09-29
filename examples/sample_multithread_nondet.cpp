#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <random>
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
    int random_salt;
    int state;
    bool flag;
};

// Global state deliberately initialized with nondeterministic entropy
RuntimeState g_state = {0, 0, 1, false};

std::atomic<bool> g_running{true};
std::mutex g_worker_mutex;
std::condition_variable g_worker_cv;
bool g_worker_ready[2] = {false, false};

thread_local int t_thread_id = 0;

__attribute__((noinline)) void observation_checkpoint() {
    asm volatile("" ::: "memory");
}

void worker_func(int id) {
    t_thread_id = id;
    {
        std::unique_lock<std::mutex> lock(g_worker_mutex);
        if (id >= 1 && id <= 2) {
            g_worker_ready[id - 1] = true;
        }
        g_worker_cv.notify_all();
        g_worker_cv.wait(lock, [&]() { return !g_running.load(); });
    }
}

int main() {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    // Intentionally nondeterministic initialization
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 999999);
    g_state.random_salt = dis(gen);
    g_state.counter = (int)(std::chrono::system_clock::now().time_since_epoch().count() % 100000);

    std::thread w1(worker_func, 1);
    std::thread w2(worker_func, 2);

    {
        std::unique_lock<std::mutex> lock(g_worker_mutex);
        g_worker_cv.wait(lock, [&]() {
            return g_worker_ready[0] && g_worker_ready[1];
        });
    }

    // Observation point where restart will yield different random_salt / counter
    observation_checkpoint();

    {
        std::lock_guard<std::mutex> lock(g_worker_mutex);
        g_running.store(false);
        g_worker_cv.notify_all();
    }
    w1.join();
    w2.join();
    return 0;
}
