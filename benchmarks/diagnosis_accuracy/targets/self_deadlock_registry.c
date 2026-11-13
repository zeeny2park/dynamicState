#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

static pthread_mutex_t reg_mu = PTHREAD_MUTEX_INITIALIZER;
static int entries;

static int count_entries(void)
{
    int n;
    pthread_mutex_lock(&reg_mu);
    n = entries;
    pthread_mutex_unlock(&reg_mu);
    return n;
}

static void *register_all(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "registrar");
    pthread_mutex_lock(&reg_mu);
    entries += 4;
    if (count_entries() > 3)
        entries = 0;
    pthread_mutex_unlock(&reg_mu);
    return NULL;
}

int main(void)
{
    pthread_t a;
    pthread_create(&a, NULL, register_all, NULL);
    usleep(500000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
