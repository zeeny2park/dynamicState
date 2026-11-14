// Healthy C++ program.  Objects whose VALID magic / tag / header values are poison-looking constants: an array of
// objects that all agree, a heap object reached through a typed pointer, a class with a static canary.
#include <cstdint>
#include <cstdio>
#include <unistd.h>

struct Header {
    uint32_t magic;
    uint32_t tag;
    uint32_t headerCrc;
    uint32_t stage;
};

class Session {
public:
    uint64_t cookie = 0xBAADF00DBAADF00Dull;
    uint32_t guardWord = 0xDEADDEADu;
    int id = 0;
};

Header g_headers[4] = { {0xDEADBEEFu, 1, 0xDEADBEEFu, 0xDEADDEADu}, {0xDEADBEEFu, 2, 0xDEADBEEFu, 0xDEADDEADu},
                        {0xDEADBEEFu, 3, 0xDEADBEEFu, 0xDEADDEADu}, {0xDEADBEEFu, 4, 0xDEADBEEFu, 0xDEADDEADu} };
Header *g_current = nullptr;
Session *g_session = nullptr;
static uint32_t s_canary = 0xBAADF00Du;

int main() {
    g_current = new Header{0xDEADBEEFu, 9, 0xBAADBAADu, 0xDEADBEEFu};
    g_session = new Session();
    (void)s_canary;
    std::puts("READY");
    std::fflush(stdout);
    for (;;) pause();
}
