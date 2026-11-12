/* Worker pool parked on a condition variable while the queue is empty. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

#define NW 4

static pthread_mutex_t qmu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER;
static int qlen;
static volatile int parked;

static void *pool_worker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "pool");
    pthread_mutex_lock(&qmu);
    for (;;) {
        while (qlen == 0) {
            parked++;
            pthread_cond_wait(&qcv, &qmu);
            parked--;
        }
        qlen--;
    }
    return NULL;
}

int main(void)
{
    pthread_t t[NW];
    for (int i = 0; i < NW; i++)
        pthread_create(&t[i], NULL, pool_worker, NULL);
    while (parked < NW)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
