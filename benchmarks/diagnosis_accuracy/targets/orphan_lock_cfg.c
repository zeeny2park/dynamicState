#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t m_cfg = PTHREAD_MUTEX_INITIALIZER;

static void *loader(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "loader");
    pthread_mutex_lock(&m_cfg);
    return NULL;
}

static void *reader(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "reader");
    pthread_mutex_lock(&m_cfg);
    pthread_mutex_unlock(&m_cfg);
    return NULL;
}

int main(void)
{
    pthread_t a, b, c;
    pthread_create(&a, NULL, loader, NULL);
    pthread_join(a, NULL);
    pthread_create(&b, NULL, reader, NULL);
    pthread_create(&c, NULL, reader, NULL);
    usleep(600000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
