#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/prctl.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

// Forward declaration of optional shared library helper
extern "C" int helper_calc(int val) __attribute__((weak));

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_worker_counter{0};

static void sigterm_handler(int) {
    g_running.store(false);
}

struct Buffer {
    uint32_t length;
    uint32_t capacity;
    char* data;
};

enum class SessionState { DISCONNECTED, CONNECTED, ERROR };

struct Session {
    SessionState state;
    uint32_t retry;
    uint32_t packet_count;
    Buffer* buffer;
    Session* parent; // Deliberate circular reference
    bool flagged;
    uint8_t priority;
    double ratio;
};

Session* global_session = nullptr;
static Session* file_session = nullptr;

struct Manager {
    Session* current;
    static Session* instance;
};

Session* Manager::instance = nullptr;
Manager g_manager{nullptr};

__attribute__((noinline)) void runtime_state_checkpoint() {
    asm volatile("" ::: "memory");
}

void worker_thread_func(Session* session) {
    while (g_running.load()) {
        g_worker_counter.fetch_add(1);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void process_packet(Session* session) {
    Buffer local_buffer{1, 2, nullptr};
    Session* local_session = session;
    uint32_t local_retry = session->retry;
    uint32_t observed_capacity = session->buffer->capacity;

    runtime_state_checkpoint(); // Snapshot point / mutation stop

    // Failure triggers
    if (session->priority == 139) {
        *(volatile int*)0 = 42; // SIGSEGV Crash
    }
    if (session->priority == 255) {
        while (session->priority == 255 && g_running.load()) {
            asm volatile("" ::: "memory"); // Timeout trigger
        }
    }

    // State machine logic
    if (session->retry == 0) {
        session->state = SessionState::DISCONNECTED;
        session->flagged = false;
    } else if (session->retry >= 3) {
        session->state = SessionState::ERROR;
        session->flagged = true;
    } else {
        session->state = SessionState::CONNECTED;
        session->packet_count += local_retry + observed_capacity + local_buffer.length;
    }

    if (helper_calc != nullptr) {
        session->packet_count = helper_calc(session->packet_count);
    }

    if (local_session == nullptr) return;
    runtime_state_checkpoint(); // Post-transition stop
}

int main(int argc, char** argv) {
    std::signal(SIGTERM, sigterm_handler);
    std::signal(SIGINT, sigterm_handler);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);

    int max_packets = (argc > 1) ? std::atoi(argv[1]) : 10;
    bool daemon_mode = (argc > 2 && std::string(argv[2]) == "--daemon");
    bool enable_threads = daemon_mode || (argc > 2 && std::string(argv[2]) == "--threads");

    char* data = new char[64]{};
    Buffer* buffer = new Buffer{64, 256, data};
    Session* session = new Session{SessionState::CONNECTED, 2, 10, buffer, nullptr, false, 7, 1.0};
    session->parent = session; // Deliberate circular reference

    global_session = session;
    file_session = session;
    Manager::instance = session;
    g_manager.current = session;

    std::thread worker;
    if (enable_threads) {
        worker = std::thread(worker_thread_func, session);
    }

    std::printf("READY: PID=%d\n", getpid());
    std::fflush(stdout);

    if (daemon_mode) {
        while (g_running.load()) {
            process_packet(session);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    } else {
        for (int i = 0; i < max_packets; ++i) {
            process_packet(session);
        }
    }

    g_running.store(false);
    if (worker.joinable()) {
        worker.join();
    }

    delete[] data;
    delete buffer;
    delete session;
    return 0;
}
