// Two tellers move money between accounts; each locks the source account, then the destination.
#include <pthread.h>
#include <unistd.h>

#include <mutex>
#include <thread>

struct Account {
    std::mutex mu;
    long balance = 1000;
};

static Account g_checking;
static Account g_savings;

static void transfer(Account &from, Account &to, long amount)
{
    std::lock_guard<std::mutex> src(from.mu);
    usleep(200000);
    std::lock_guard<std::mutex> dst(to.mu);
    from.balance -= amount;
    to.balance += amount;
}

int main()
{
    std::thread a([] {
        pthread_setname_np(pthread_self(), "teller_a");
        transfer(g_checking, g_savings, 10);
    });
    std::thread b([] {
        pthread_setname_np(pthread_self(), "teller_b");
        transfer(g_savings, g_checking, 25);
    });
    usleep(900000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
