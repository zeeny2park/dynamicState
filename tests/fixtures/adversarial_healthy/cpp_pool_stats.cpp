// Healthy C++ program.  camelCase counters: a REAL alloc/free pair (allocCount / freeCount) that stays balanced,
// an unrelated growing allocBytesTotal, a capacity/length pair that holds (queueLen <= queueCap), fields that share
// a role word but not a stem (maxPending / pendingBytes), a valid 0xDEADBEEF magic, and large but steady
// containers.
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

struct Pool {
    uint32_t m_magic = 0xDEADBEEFu;
    long allocCount = 0;
    long freeCount = 0;
    long allocBytesTotal = 0;
    size_t maxPending = 4;
    size_t pendingBytes = 65536;
    size_t queueCap = 16;
    size_t queueLen = 3;
    std::vector<int> registry;
};

Pool g_pool;
std::map<int, std::string> g_cache;

int main() {
    g_pool.registry.assign(500, 7);
    for (int i = 0; i < 200; i++) g_cache[i] = "value";
    std::puts("READY");
    std::fflush(stdout);
    for (;;) {
        int *p = new int[16];
        g_pool.allocCount++;
        g_pool.allocBytesTotal += 64;
        delete[] p;
        g_pool.freeCount++;
        usleep(1000);
    }
}
