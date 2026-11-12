/* Healthy use-after-free control: a program-managed object pool.  "Released" objects go on the program's own
 * free list (g_pool_free) and are rewritten while on it; to glibc every pool object is an IN-USE chunk.  A
 * pointer to the last released object is kept (g_last_released).  A second thread does genuine malloc/free
 * churn of other sizes (no pointer is kept to a freed block).  Nothing is ever used after glibc free().
 * Prints READY.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct obj {
    struct obj *next;
    long generation;
    char payload[48];
};

#define NOBJ 16
struct obj *g_pool_free;
struct obj *g_in_use[NOBJ];
struct obj *g_last_released;
pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;

static struct obj *pool_get(void)
{
    struct obj *o = g_pool_free;
    if (o)
        g_pool_free = o->next;
    return o;
}

static void pool_put(struct obj *o)
{
    o->generation++;                       /* written while on the program's own free list */
    memset(o->payload, (int)(o->generation & 0x7f), sizeof o->payload);
    o->next = g_pool_free;
    g_pool_free = o;
    g_last_released = o;
}

static void *churn(void *arg)
{
    (void)arg;
    struct timespec ts = {0, 2 * 1000 * 1000};
    for (unsigned n = 0;; n++) {
        char *p = malloc(24 + (n % 5) * 40);
        memset(p, 'c', 24);
        free(p);
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    for (int i = 0; i < NOBJ; i++)
        pool_put(calloc(1, sizeof(struct obj)));
    pthread_t t;
    pthread_create(&t, NULL, churn, NULL);
    printf("READY\n");
    fflush(stdout);
    struct timespec ts = {0, 5 * 1000 * 1000};
    for (unsigned n = 0;; n++) {
        pthread_mutex_lock(&g_pool_lock);
        int k = (int)(n % NOBJ);
        if (g_in_use[k]) {
            pool_put(g_in_use[k]);
            g_in_use[k] = NULL;
        } else {
            g_in_use[k] = pool_get();
        }
        pthread_mutex_unlock(&g_pool_lock);
        nanosleep(&ts, NULL);
    }
}
