// Healthy C++ program, steady memory.  Containers named like leaks / caches that are large but bounded, a struct
// whose pointer + "count" member is a statistic (it grows; memory does not), and a statistics block with
// leak/retained/pool words in its member names.
#include <cstdio>
#include <deque>
#include <list>
#include <string>
#include <unistd.h>
#include <vector>

struct Stats {
    long leakChecks = 0;
    long retainedHits = 0;
    long poolReuses = 0;
};

struct Arena {
    char *base = nullptr;
    long count = 0;          // number of resets performed: grows, owns nothing
};

std::vector<std::string> g_leak_registry;
std::list<int> g_retained;
std::deque<int> g_pool_queue;
Stats g_stats;
Arena g_arena;

int main() {
    g_leak_registry.assign(300, std::string(16, 'x'));
    for (int i = 0; i < 100; i++) g_retained.push_back(i);
    for (int i = 0; i < 100; i++) g_pool_queue.push_back(i);
    g_arena.base = new char[1 << 16];
    std::puts("READY");
    std::fflush(stdout);
    for (;;) {
        g_arena.count += 5;
        g_stats.leakChecks += 2;
        g_stats.retainedHits += 3;
        g_stats.poolReuses += 1;
        g_pool_queue.push_back(1);
        g_pool_queue.pop_front();
        usleep(1000);
    }
}
