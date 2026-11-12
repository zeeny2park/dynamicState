#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t m_in = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m_out = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t bar;

static void *ingest(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "ingest");
    pthread_mutex_lock(&m_in);
    pthread_barrier_wait(&bar);
    pthread_mutex_lock(&m_out);
    pthread_mutex_unlock(&m_out);
    pthread_mutex_unlock(&m_in);
    return NULL;
}

static void *flush(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "flush");
    pthread_mutex_lock(&m_out);
    pthread_barrier_wait(&bar);
    pthread_mutex_lock(&m_in);
    pthread_mutex_unlock(&m_in);
    pthread_mutex_unlock(&m_out);
    return NULL;
}

int main(void)
{
    pthread_t a, b;
    pthread_barrier_init(&bar, NULL, 2);
    pthread_create(&a, NULL, ingest, NULL);
    pthread_create(&b, NULL, flush, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
