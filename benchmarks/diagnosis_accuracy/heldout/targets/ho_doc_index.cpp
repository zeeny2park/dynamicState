// Document index: every ingested document is appended to the index and kept for lookups.
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <vector>

struct Doc {
    unsigned id;
    char text[480];
};

class DocIndex {
public:
    void add(unsigned id)
    {
        Doc *d = new Doc;
        d->id = id;
        std::memset(d->text, 'd', sizeof d->text);
        docs_.push_back(d);
    }
    size_t size() const { return docs_.size(); }

private:
    std::vector<Doc *> docs_;
};

static DocIndex g_index;
static std::atomic<unsigned> g_ingested{0};

static void *ingest(void *)
{
    pthread_setname_np(pthread_self(), "ingest");
    for (unsigned k = 0;; k++) {
        g_index.add(k);
        g_ingested++;
        usleep(300);
        /* FIXTURE_CAP: ~1.5 MiB/s; stop at ~200 MiB, stay alive. */
        if (k >= 400000u)
            for (;;)
                pause();
    }
    return nullptr;
}

int main()
{
    pthread_t t;
    pthread_create(&t, nullptr, ingest, nullptr);
    while (g_ingested < 3000)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
