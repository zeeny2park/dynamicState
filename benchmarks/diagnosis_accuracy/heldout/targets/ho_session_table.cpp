// Session table: sessions are opened per client; the oldest ones are retired when the table gets long.
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

struct Session {
    int fd;
    std::string user;
    char scratch[400];
};

class SessionTable {
public:
    void open(int fd)
    {
        Session *s = new Session();
        s->fd = fd;
        s->user = "guest";
        live_.push_back(s);
    }

    void retire_oldest()
    {
        if (live_.size() > 64)
            live_.erase(live_.begin());
    }

private:
    std::vector<Session *> live_;
};

static SessionTable g_sessions;
static std::atomic<unsigned> g_opened{0};

static void serve_clients()
{
    pthread_setname_np(pthread_self(), "sessions");
    for (int fd = 3;; fd++) {
        g_sessions.open(fd);
        g_sessions.retire_oldest();
        g_opened++;
        usleep(300);
        /* FIXTURE_CAP: ~1.4 MiB/s; stop at ~200 MiB, stay alive. */
        if (g_opened >= 420000u)
            for (;;)
                pause();
    }
}

int main()
{
    std::thread worker(serve_clients);
    while (g_opened < 3000)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
