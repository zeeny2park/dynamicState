/* IMP-007 fixture: >= 64MB main-arena heap of mixed size classes, some freed, some leaked, plus a
 * spinning thread that advances g_progress so a test can prove the target kept running while the
 * heap was walked.  Prints:
 *   STATS <live> <leaked> <freed> <bytes_requested> <many_count>
 *   PROGRESS <addr-of-g_progress>
 *   LEAK <addr> <size>      (one per leaked block)
 *   READY
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OBF 0xA5A5A5A55A5A5A5AULL

void **g_many;
size_t g_many_count;
volatile unsigned long g_progress;
uintptr_t *g_leak_obf;
size_t *g_leak_size;
size_t g_nleak;

static void *spinner(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "spinner");
    for (;;)
        g_progress++;
    return NULL;
}

static void __attribute__((noinline)) scrub_stack(void)
{
    volatile char pad[65536];
    memset((char *)pad, 0, sizeof(pad));
}

static void __attribute__((noinline)) build(size_t target)
{
    static const size_t classes[] = {48, 200, 1000, 4000, 24, 520};
    size_t cap = target / 24 + 16;
    g_many = malloc(cap * sizeof(void *));
    g_leak_obf = malloc(4096 * sizeof(uintptr_t));
    g_leak_size = malloc(4096 * sizeof(size_t));
    size_t total = 0, i = 0;
    while (total < target && i < cap) {
        size_t sz = classes[i % 6];
        g_many[i] = malloc(sz);
        memset(g_many[i], (int)(i & 0x7f), sz < 64 ? sz : 64);
        total += sz;
        i++;
    }
    g_many_count = i;
    size_t freed = 0, leaked = 0;
    for (size_t k = 0; k < g_many_count; k++) {
        if (k % 10 == 3) {
            free(g_many[k]);
            g_many[k] = NULL;
            freed++;
        } else if (k % 997 == 5 && g_nleak < 4096) {
            g_leak_obf[g_nleak] = (uintptr_t)g_many[k] ^ OBF;
            g_leak_size[g_nleak] = classes[k % 6];
            g_nleak++;
            g_many[k] = NULL;
            leaked++;
        }
    }
    printf("STATS %zu %zu %zu %zu %zu\n", g_many_count - freed - leaked, leaked, freed, total, g_many_count);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);
    build((size_t)64 * 1024 * 1024);
    printf("PROGRESS %p\n", (void *)&g_progress);
    for (size_t k = 0; k < g_nleak; k++)
        printf("LEAK 0x%lx %zu\n", (unsigned long)(g_leak_obf[k] ^ OBF), g_leak_size[k]);
    pthread_t th;
    pthread_create(&th, NULL, spinner, NULL);
    printf("READY\n");
    fflush(stdout);
    scrub_stack();
    for (;;)
        pause();
    return 0;
}
