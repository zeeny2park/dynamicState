// Plugin registry: registration checks the current count before inserting.
#include <pthread.h>
#include <unistd.h>

#include <map>
#include <mutex>
#include <string>
#include <thread>

class Registry {
public:
    size_t count()
    {
        std::lock_guard<std::mutex> hold(mu_);
        return plugins_.size();
    }

    void add(const std::string &name, int version)
    {
        std::lock_guard<std::mutex> hold(mu_);
        if (count() < 64)
            plugins_[name] = version;
    }

private:
    std::mutex mu_;
    std::map<std::string, int> plugins_;
};

static Registry g_registry;

int main()
{
    std::thread loader([] {
        pthread_setname_np(pthread_self(), "plugin_loader");
        g_registry.add("codec", 3);
    });
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
