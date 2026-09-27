#include <cstdint>

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

void process_packet(Session* session) {
    Buffer local_buffer{1, 2, nullptr};
    Session* local_session = session;
    uint32_t local_retry = session->retry;
    uint32_t observed_capacity = session->buffer->capacity;
    runtime_state_checkpoint();  // Snapshot A / mutation stop.
    if (session->retry >= 3) {
        session->state = SessionState::ERROR;
        session->flagged = true;
    } else {
        session->packet_count += local_retry + observed_capacity + local_buffer.length;
    }
    if (local_session == nullptr) return;
    runtime_state_checkpoint();  // Snapshot B stop.
}

int main() {
    char* data = new char[64]{};
    Buffer* buffer = new Buffer{64, 256, data};
    Session* session = new Session{SessionState::CONNECTED, 2, 10, buffer, nullptr, false, 7};
    session->parent = session;  // Deliberate circular reference for traversal validation.
    global_session = session;
    file_session = session;
    Manager::instance = session;
    g_manager.current = session;
    process_packet(session);
    return session->packet_count == 0;
}
