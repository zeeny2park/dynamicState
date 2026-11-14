#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include "journal.h"

static volatile unsigned appended;

static void *appender(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "appender");
    for (unsigned s = 0;; s++) {
        journal_append(s);
        appended = s + 1;
        usleep(400);
        /* FIXTURE_CAP: ~1.7 MiB/s; stop at ~200 MiB, stay alive. */
        if (s >= 280000u)
            for (;;)
                pause();
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, appender, NULL);
    while (appended < 2500)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
