/* A worker thread builds a large index of small nodes, keeps one in five and then waits for more work. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NNODE 110000
#define NODESZ 200

static void *nodes[NNODE];
static volatile int built;

static void *indexer(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "indexer");
    for (unsigned i = 0; i < NNODE; i++) {
        nodes[i] = malloc(NODESZ);
        if (nodes[i])
            memset(nodes[i], 7, NODESZ);
    }
    for (unsigned i = 0; i < NNODE; i++) {
        if (i % 5) {
            free(nodes[i]);
            nodes[i] = NULL;
        }
    }
    built = 1;
    for (;;)
        pause();
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, indexer, NULL);
    while (!built)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
