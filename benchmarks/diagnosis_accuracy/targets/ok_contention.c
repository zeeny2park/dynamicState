/* Four threads fight over one lock with short critical sections; everyone always gets through. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

static pthread_mutex_t shared_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile unsigned long total;
static volatile unsigned long per[4];

static void *contender(void *arg)
{
    int me = (int)(intptr_t)arg;
    pthread_setname_np(pthread_self(), "contend");
    for (;;) {
        pthread_mutex_lock(&shared_mu);
        total++;
        per[me]++;
        for (volatile int i = 0; i < 2000; i++)
            ;
        pthread_mutex_unlock(&shared_mu);
        usleep(100);
    }
    return NULL;
}

int main(void)
{
    pthread_t t[4];
    for (intptr_t i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, contender, (void *)i);
    while (total < 500)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
