#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t m_state = PTHREAD_MUTEX_INITIALIZER;

static void refresh(void)
{
    pthread_mutex_lock(&m_state);
    pthread_mutex_unlock(&m_state);
}

static void *worker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "refresher");
    pthread_mutex_lock(&m_state);
    refresh();
    pthread_mutex_unlock(&m_state);
    return NULL;
}

int main(void)
{
    pthread_t a;
    pthread_create(&a, NULL, worker, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
