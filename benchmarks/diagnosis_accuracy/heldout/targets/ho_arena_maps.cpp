// Block arena: grows by asking its page source for another block; blocks are kept until the arena is reset.
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <vector>

typedef void *(*page_source_fn)(size_t);

static void *map_block(size_t bytes)
{
    void *p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? nullptr : p;
}

class Arena {
public:
    Arena(page_source_fn src, size_t block) : source_(src), block_(block) {}

    void *grow()
    {
        void *b = source_(block_);
        if (b) {
            std::memset(b, 0x5a, block_);
            blocks_.push_back(b);
        }
        return b;
    }

    size_t blocks() const { return blocks_.size(); }

private:
    page_source_fn source_;
    size_t block_;
    std::vector<void *> blocks_;
};

static Arena g_arena(map_block, 512 * 1024);

static void *builder(void *)
{
    pthread_setname_np(pthread_self(), "builder");
    /* FIXTURE_CAP: 512 KiB per 100 ms; stop at 400 blocks (~200 MiB), stay alive. */
    while (g_arena.blocks() < 400) {
        g_arena.grow();
        usleep(100000);
    }
    for (;;)
        pause();
    return nullptr;
}

int main()
{
    pthread_t t;
    pthread_create(&t, nullptr, builder, nullptr);
    while (g_arena.blocks() < 6)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
