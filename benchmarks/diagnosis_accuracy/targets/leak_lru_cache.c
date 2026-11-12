/* Small fixed-capacity LRU cache with a chained hash index (style after common textbook versions). */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NB 64
#define CAP 128

struct node {
    struct node *prev, *next;   /* recency list */
    struct node *chain;         /* hash bucket chain */
    unsigned key;
    char val[512];
};

struct lru {
    struct node *head, *tail;
    struct node *tab[NB];
    unsigned n;
};

static struct lru cache;
static volatile unsigned puts_done;

static void list_unlink(struct lru *c, struct node *x)
{
    if (x->prev) x->prev->next = x->next; else c->head = x->next;
    if (x->next) x->next->prev = x->prev; else c->tail = x->prev;
}

static void lru_evict(struct lru *c)
{
    struct node *x = c->tail;
    struct node **pp = &c->tab[x->key % NB];
    list_unlink(c, x);
    while (*pp != x)
        pp = &(*pp)->chain;
    *pp = x->chain;
    c->n--;
}

static void lru_put(struct lru *c, unsigned key)
{
    struct node *x = calloc(1, sizeof *x);
    if (!x)
        return;
    x->key = key;
    memset(x->val, 'v', sizeof x->val - 1);
    x->chain = c->tab[key % NB];
    c->tab[key % NB] = x;
    x->next = c->head;
    if (c->head) c->head->prev = x;
    c->head = x;
    if (!c->tail) c->tail = x;
    if (++c->n > CAP)
        lru_evict(c);
}

static void *filler(void *arg)
{
    unsigned k = 0;
    (void)arg;
    pthread_setname_np(pthread_self(), "filler");
    for (;;) {
        lru_put(&cache, k++);
        puts_done++;
        usleep(300);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    pthread_create(&t, NULL, filler, NULL);
    while (puts_done < 3000)
        usleep(10000);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
