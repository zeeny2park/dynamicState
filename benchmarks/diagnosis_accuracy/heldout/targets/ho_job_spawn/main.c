/* Report exporter: every export request starts a job that waits for its upload channel. */
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include "jobs.h"

static int channel[2];
static volatile int requests;

static void *export_job(void *arg)
{
    char c;
    (void)arg;
    pthread_setname_np(pthread_self(), "exporter");
    while (read(channel[0], &c, 1) != 1)
        ;
    return NULL;
}

static void handle_requests(void)
{
    /* FIXTURE_CAP: one job per 100 ms; stop at 300 jobs, stay alive. */
    for (int n = 0; n < 300; n++) {
        if (start_job(export_job, NULL) != 0)
            break;
        requests++;
        usleep(100000);
    }
}

static void *frontend(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "frontend");
    handle_requests();
    for (;;)
        pause();
    return NULL;
}

int main(void)
{
    pthread_t f;
    if (pipe(channel) != 0)
        return 1;
    pthread_create(&f, NULL, frontend, NULL);
    while (requests < 12)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
