/* IMP-008 fixture: only large blocks leak (each above glibc's mmap threshold, so every one is its own
 * mmapped chunk; nothing is ever freed, so the threshold never rises).  Ground truth: unreachable mmapped
 * blocks of request size LARGE, allocated by thread "uploader".  Prints the ground truth and READY. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LARGE (320 * 1024)

static volatile unsigned g_uploads;

static void *uploader(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "uploader");
    for (;;) {
        char *buf = malloc(LARGE);
        if (!buf)
            break;
        for (size_t i = 0; i < LARGE; i += 4096)
            buf[i] = (char)i;
        g_uploads++;          /* buf dropped */
        usleep(20000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, uploader, NULL);
    while (g_uploads < 10)
        usleep(10000);
    printf("GT leak_request_size=%d mmapped=1 thread=uploader\nREADY\n", LARGE);
    fflush(stdout);
    for (;;)
        pause();
}
