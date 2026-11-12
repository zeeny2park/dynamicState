/* IMP-009 fixture: a thread with a small pthread stack recurses until only a few KiB are left above its
 * guard region and then blocks in a system call; a second thread with the same stack size idles in a
 * shallow frame (must not be reported).
 *
 * Prints (from main): DEEP <tid> deep_worker <stack lo> <stack size> <approx margin>, SHALLOW <tid>
 * shallow_worker, READY.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define STACK_SIZE (256 * 1024)
#define STOP_MARGIN (12 * 1024)

static uintptr_t g_lo;
static long g_deep_tid, g_shallow_tid;
static unsigned long g_margin;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static int g_ready;
volatile unsigned long g_depth;

static void announce(void)
{
    pthread_mutex_lock(&g_mu);
    g_ready++;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
}

static void dive(unsigned long n)
{
    volatile char pad[1024];
    memset((char *)pad, (int)(n & 0xff), sizeof pad);
    g_depth = n;
    if ((uintptr_t)pad - g_lo > STOP_MARGIN) {
        dive(n + 1);
    } else {
        /* no printf here (it needs stack): main prints the ground truth */
        g_deep_tid = (long)syscall(SYS_gettid);
        g_margin = (unsigned long)((uintptr_t)pad - g_lo);
        announce();
        for (;;)
            pause();
    }
    pad[0]++;
}

static void *deep(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "deep_worker");
    pthread_attr_t a;
    void *lo;
    size_t sz;
    pthread_getattr_np(pthread_self(), &a);
    pthread_attr_getstack(&a, &lo, &sz);
    g_lo = (uintptr_t)lo;
    dive(0);
    return NULL;
}

static void *shallow(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "shallow_worker");
    g_shallow_tid = (long)syscall(SYS_gettid);
    announce();
    for (;;)
        pause();
    return NULL;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 14);
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, STACK_SIZE);
    pthread_t t1, t2;
    pthread_create(&t1, &a, deep, NULL);
    pthread_create(&t2, &a, shallow, NULL);
    pthread_mutex_lock(&g_mu);
    while (g_ready < 2)
        pthread_cond_wait(&g_cv, &g_mu);
    pthread_mutex_unlock(&g_mu);
    printf("DEEP %ld deep_worker 0x%lx %d %lu\n", g_deep_tid, (unsigned long)g_lo, STACK_SIZE, g_margin);
    printf("SHALLOW %ld shallow_worker\n", g_shallow_tid);
    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
