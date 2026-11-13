/* Loader keeps every 256 KiB slab it maps in a table and never unmaps one. */
#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SLAB (256u << 10)
#define MAXSLABS 3000

static void *slabs[MAXSLABS];
static volatile unsigned nslabs;

static void *loader(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "loader");
    while (nslabs < MAXSLABS) {
        void *p = mmap(NULL, SLAB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            break;
        memset(p, 0x5a, SLAB);
        slabs[nslabs] = p;
        nslabs++;
        usleep(50000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, loader, NULL);
    while (nslabs < 20)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
