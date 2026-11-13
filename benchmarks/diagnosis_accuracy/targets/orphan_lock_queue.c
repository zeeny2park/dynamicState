#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
static int pending = 3;

static void *producer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "producer");
    pthread_mutex_lock(&q_mu);
    if (pending > 0)
        pthread_exit(NULL);
    pthread_mutex_unlock(&q_mu);
    return NULL;
}

static void *drainer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "drainer");
    usleep(300000);
    pthread_mutex_lock(&q_mu);
    pending = 0;
    pthread_mutex_unlock(&q_mu);
    return NULL;
}

int main(void)
{
    pthread_t a, b;
    pthread_create(&a, NULL, producer, NULL);
    pthread_join(a, NULL);
    pthread_create(&b, NULL, drainer, NULL);
    usleep(800000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
