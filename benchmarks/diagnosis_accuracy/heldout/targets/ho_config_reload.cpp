// Configuration reload: a one-shot reload thread bumps the version; readers take the lock to read it.
#include <pthread.h>
#include <unistd.h>

#include <mutex>
#include <thread>

static std::mutex g_cfg_mu;
static int g_cfg_version;
static volatile int g_reads;

static void reload()
{
    g_cfg_mu.lock();
    g_cfg_version++;
    if (g_cfg_version > 0)
        return;
    g_cfg_mu.unlock();
}

static void read_config()
{
    pthread_setname_np(pthread_self(), "cfg_reader");
    for (;;) {
        std::lock_guard<std::mutex> hold(g_cfg_mu);
        g_reads += g_cfg_version;
    }
}

int main()
{
    std::thread r([] {
        pthread_setname_np(pthread_self(), "reloader");
        reload();
    });
    r.join();
    std::thread a(read_config);
    std::thread b(read_config);
    usleep(600000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
