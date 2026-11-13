/* A region pool: every refill maps a fresh 1 MiB region and chains it in front; regions are never returned. */
#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define REGION (1u << 20)
#define MAXREGIONS 600

struct region {
    struct region *prev;
    size_t used;
    char data[];
};

struct pool {
    struct region *head;
    unsigned regions;
};

static struct pool store;

static void refill(void)
{
    struct region *r = mmap(NULL, REGION, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED)
        return;
    memset(r->data, 0x33, REGION - sizeof *r);
    r->used = REGION - sizeof *r;
    r->prev = store.head;
    store.head = r;
    store.regions++;
}

static void *filler(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "filler");
    while (store.regions < MAXREGIONS) {
        refill();
        usleep(150000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, filler, NULL);
    while (store.regions < 4)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
