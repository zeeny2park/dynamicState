// Every accepted client gets its own detached session thread, which waits for the server to shut down.
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

static std::mutex g_mu;
static std::condition_variable g_cv;
static bool g_shutdown = false;
static std::atomic<int> g_accepted{0};

static void serve(int client)
{
    pthread_setname_np(pthread_self(), "session");
    std::unique_lock<std::mutex> lk(g_mu);
    g_cv.wait(lk, [] { return g_shutdown; });
    (void)client;
}

static void accept_loop()
{
    pthread_setname_np(pthread_self(), "acceptor");
    /* FIXTURE_CAP: one thread per 100 ms; stop at 300 threads, stay alive. */
    for (int c = 0; c < 300; c++) {
        std::thread(serve, c).detach();
        g_accepted++;
        usleep(100000);
    }
    for (;;)
        pause();
}

int main()
{
    std::thread acc(accept_loop);
    while (g_accepted < 12)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
