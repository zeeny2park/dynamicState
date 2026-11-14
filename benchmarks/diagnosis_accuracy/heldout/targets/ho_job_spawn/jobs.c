/* Background job runner: each job runs on its own thread. */
#include <pthread.h>
#include "jobs.h"

int start_job(job_fn fn, void *arg)
{
    pthread_t tid;
    return pthread_create(&tid, NULL, fn, arg);
}
