#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
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

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_counter{0};

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
    Session* parent;
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

void worker_thread(Session* session) {
    while (g_running.load()) {
        g_counter.fetch_add(1);
        session->packet_count++;
        if ((session->packet_count % 10) == 0) {
            session->retry = (session->retry + 1) % 5;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

int main(int argc, char** argv) {
    std::signal(SIGTERM, sigterm_handler);
    std::signal(SIGINT, sigterm_handler);
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    int duration_sec = (argc > 1) ? std::atoi(argv[1]) : 30;

    char* data = new char[64]{};
    Buffer* buffer = new Buffer{64, 256, data};
    Session* session = new Session{SessionState::CONNECTED, 2, 100, buffer, nullptr, false, 7, 1.0};
    session->parent = session; // Circular self-reference
    global_session = session;
    file_session = session;
    Manager::instance = session;
    g_manager.current = session;

    std::thread th(worker_thread, session);

    // Print PID and flush so parent test process can capture it
    std::printf("READY: PID=%d\n", getpid());
    std::fflush(stdout);

    // Run for requested duration or until stopped
    for (int i = 0; i < duration_sec * 10; ++i) {
        if (!g_running.load()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    g_running.store(false);
    if (th.joinable()) {
        th.join();
    }

    std::printf("EXIT: PID=%d, FINAL_COUNTER=%lu, PACKET_COUNT=%u\n",
                getpid(), g_counter.load(), session->packet_count);
    std::fflush(stdout);

    delete[] data;
    delete buffer;
    delete session;
    return 0;
}
