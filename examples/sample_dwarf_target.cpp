#include <unistd.h>
#include <cstdio>

struct State {
    int counter;
};

struct Worker {
    State state;
};

struct Session {
    Worker worker;
};

Session g_session;

int main() {
    g_session.worker.state.counter = 42;
    printf("Sample DWARF target running. PID: %d, counter: %d\n", getpid(), g_session.worker.state.counter);
    fflush(stdout);

    while (true) {
        usleep(100000);
    }
    return 0;
}
