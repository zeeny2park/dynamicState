/* Bounded job queue: a producer fills it, workers take jobs; the producer gives up when the queue is full. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

#define Q_CAP 16
#define Q_LOCK(q) pthread_mutex_lock(&(q)->lock)
#define Q_UNLOCK(q) pthread_mutex_unlock(&(q)->lock)

struct job_queue {
    pthread_mutex_t lock;
    int items[Q_CAP];
    int n;
};

struct job_queue jobs = { PTHREAD_MUTEX_INITIALIZER, {0}, 0 };
volatile long done_jobs;

static void *producer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "producer");
    for (int k = 0;; k++) {
        Q_LOCK(&jobs);
        if (jobs.n == Q_CAP)
            return NULL;
        jobs.items[jobs.n++] = k;
        Q_UNLOCK(&jobs);
    }
}

static void *worker(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "q_worker");
    usleep(100000);
    for (;;) {
        Q_LOCK(&jobs);
        if (jobs.n > 0)
            done_jobs += jobs.items[--jobs.n];
        Q_UNLOCK(&jobs);
        usleep(1000);
    }
    return NULL;
}

int main(void)
{
    pthread_t p, w1, w2;
    pthread_create(&p, NULL, producer, NULL);
    pthread_join(p, NULL);
    pthread_create(&w1, NULL, worker, NULL);
    pthread_create(&w2, NULL, worker, NULL);
    usleep(700000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
