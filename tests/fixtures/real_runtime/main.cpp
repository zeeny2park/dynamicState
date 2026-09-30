#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <unistd.h>
#include <signal.h>

struct State {
    int counter;
    int flags;
};

struct HeapState {
    int counter;
};

struct SharedNode {
    int value;
    SharedNode* next;
};

struct Worker {
    State state;
    HeapState* heap_state;
    SharedNode* shared;
};

struct Session {
    Worker worker;
};

struct ThreadCounter {
    uint64_t counter;
};

// Global root instances
Session g_session;
HeapState* g_heap_state = nullptr;
SharedNode g_node_a;
SharedNode g_node_b;

ThreadCounter g_thread_a;
ThreadCounter g_thread_b;
volatile uint64_t g_heartbeat = 0;
std::atomic<bool> g_running{true};

void worker_a_fn() {
    while (g_running.load(std::memory_order_relaxed)) {
        g_thread_a.counter++;
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

void worker_b_fn() {
    while (g_running.load(std::memory_order_relaxed)) {
        g_thread_b.counter++;
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

void handle_signal(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char** argv) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    // 1. Establish runtime state per requirement specification
    g_session.worker.state.counter = 42;
    g_session.worker.state.flags = 7;

    g_heap_state = new HeapState();
    g_heap_state->counter = 99;

    g_session.worker.heap_state = g_heap_state;

    g_node_a.value = 111;
    g_node_b.value = 222;

    g_node_a.next = &g_node_b;
    g_node_b.next = &g_node_a;

    g_session.worker.shared = &g_node_a;

    g_thread_a.counter = 1000;
    g_thread_b.counter = 2000;

    // 2. Launch multithreaded concurrent workers
    std::thread t1(worker_a_fn);
    std::thread t2(worker_b_fn);

    // 3. Precise synchronization: print READY to stdout and flush
    std::cout << "READY" << std::endl;
    std::cout.flush();

    // 4. Heartbeat loop keeping process active and proving execution resume
    while (g_running.load(std::memory_order_relaxed)) {
        g_heartbeat++;
        usleep(1000); // 1 millisecond
    }

    t1.join();
    t2.join();
    delete g_heap_state;
    return 0;
}
