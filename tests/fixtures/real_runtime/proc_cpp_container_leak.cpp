// Stage 3 fixture: C++ (libstdc++) containers owned by globals, one of which grows without bound.
//
//   proc_cpp_container_leak vector   thread "intake" appends new Record* to std::vector g_registry
//   proc_cpp_container_leak map      thread "intake" inserts into std::map<long, Session> g_sessions
//   proc_cpp_container_leak string   thread "intake" appends to std::string g_journal
//   proc_cpp_container_leak static   nothing grows (decoder ground truth only)
//
// Every mode also builds a fixed set of containers with known sizes (the decoder ground truth): an
// unordered_map, a deque, a list, a set, a shared_ptr held twice plus a weak_ptr, a unique_ptr, a short (SSO)
// and a long string.  The ground truth is printed as "GT key=value" lines, then READY once the growing
// container holds a few hundred elements.  The growing thread prints nothing after READY.
#include <pthread.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

struct Record {
    long seq;
    char payload[56];
};

struct Session {
    long id;
    char user[40];
};

struct Settings {
    int level;
    char tag[28];
};

std::vector<Record *> g_registry;
std::map<long, Session> g_sessions;
std::string g_journal;

std::unordered_map<long, long> g_index;
std::deque<long> g_backlog;
std::list<long> g_history;
std::set<long> g_ids;
std::shared_ptr<Settings> g_settings;
std::shared_ptr<Settings> g_settings_alias;
std::weak_ptr<Settings> g_settings_observer;
std::unique_ptr<Settings> g_owner;
std::string g_short_name = "short";
std::string g_long_name;

static volatile long g_count;
static const char *g_mode = "static";

static void build_fixed()
{
    for (long i = 0; i < 37; i++)
        g_index[i] = i * 3;
    for (long i = 0; i < 700; i++)          // spans several deque buffers (64 longs each)
        g_backlog.push_back(i);
    for (long i = 0; i < 21; i++)
        g_history.push_back(i);
    for (long i = 0; i < 13; i++)
        g_ids.insert(i * 7);
    g_settings = std::make_shared<Settings>();
    g_settings->level = 5;
    g_settings_alias = g_settings;
    g_settings_observer = g_settings;
    g_owner.reset(new Settings());
    g_owner->level = 9;
    g_long_name.assign(100, 'x');
}

static void *intake(void *)
{
    pthread_setname_np(pthread_self(), "intake");
    for (;;) {
        if (!std::strcmp(g_mode, "vector")) {
            Record *r = new Record();
            r->seq = g_count;
            g_registry.push_back(r);
        } else if (!std::strcmp(g_mode, "map")) {
            Session s;
            s.id = g_count;
            std::snprintf(s.user, sizeof s.user, "user-%ld", (long)g_count);
            g_sessions[s.id] = s;
        } else if (!std::strcmp(g_mode, "string")) {
            g_journal.append("entry accepted; ");
        } else {
            pause();
        }
        g_count++;
        usleep(500);
        // FIXTURE_CAP: at most ~0.2 MiB/s in every mode; stop growing at 400000 elements (< 60 MiB), stay alive.
        if (g_count >= 400000)
            for (;;)
                pause();
    }
    return nullptr;
}

int main(int argc, char **argv)
{
    if (argc > 1)
        g_mode = argv[1];
    build_fixed();
    pthread_t t;
    pthread_create(&t, nullptr, intake, nullptr);
    if (std::strcmp(g_mode, "static"))
        while (g_count < 300)
            usleep(10000);
    std::printf("GT mode=%s thread=intake\n", g_mode);
    std::printf("GT g_index=%zu g_backlog=%zu g_history=%zu g_ids=%zu\n", g_index.size(), g_backlog.size(),
                g_history.size(), g_ids.size());
    std::printf("GT g_settings_use=%ld g_settings_ptr=%p g_owner_ptr=%p\n", g_settings.use_count(),
                (void *)g_settings.get(), (void *)g_owner.get());
    std::printf("GT g_short_name=%zu g_long_name=%zu g_long_name_cap=%zu\n", g_short_name.size(),
                g_long_name.size(), g_long_name.capacity());
    std::printf("READY\n");
    std::fflush(stdout);
    for (;;)
        pause();
}
