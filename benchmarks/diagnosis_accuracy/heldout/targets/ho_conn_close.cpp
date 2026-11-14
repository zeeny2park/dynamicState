// Connection bookkeeping: the active connection is closed, then traffic is accounted to it.
#include <unistd.h>

#include <cstring>

class Conn {
public:
    explicit Conn(int fd) : fd_(fd) { std::memset(peer_, 0, sizeof peer_); }

    void account(long n)
    {
        bytes_in_ += n;
        packets_++;
    }

    int fd() const { return fd_; }

private:
    int fd_;
    long bytes_in_ = 0;
    long bytes_out_ = 0;
    long packets_ = 0;
    char peer_[40];
};

static Conn *g_active;
static Conn *g_standby;

static void close_conn(Conn *c)
{
    delete c;
}

int main()
{
    g_active = new Conn(7);
    g_standby = new Conn(8);
    g_active->account(512);
    close_conn(g_active);
    g_active->account(4096);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
