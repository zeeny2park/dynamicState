// Startup gate: the watcher waits until the loader publishes that the data set is ready.
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <thread>

static std::atomic<bool> g_ready{false};
static std::atomic<unsigned long> g_polls{0};

static void wait_until_ready()
{
    while (!g_ready.load(std::memory_order_acquire))
        g_polls.fetch_add(1, std::memory_order_relaxed);
}

int main()
{
    std::thread w([] {
        pthread_setname_np(pthread_self(), "watcher");
        wait_until_ready();
    });
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
