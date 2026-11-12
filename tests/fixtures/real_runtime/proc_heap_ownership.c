/* IMP-007 ground-truth fixture: heap ownership (address -> variable) and leak candidates.
 *
 * Builds a heap with known owners, prints the ground truth on stdout and then blocks forever
 * (every thread sleeps in pause()), so the heap is in a steady state while the test samples.
 *
 * Output lines (all addresses are user pointers as returned by malloc):
 *   BLOCK  <addr> <size> <path>                          block owned by a global/static path
 *   OPAQUE <addr> <size> <untyped-parent-path>           block referenced only from inside an
 *                                                         untyped (void*) parent block
 *   LOCAL  <addr> <size> <thread> <function> <variable>  block referenced only by a local variable
 *   LEAK   <addr> <size>                                 pointer erased: no reference anywhere
 *   FREED  <addr> <size>                                 freed block (tcache / fastbin / bins)
 *   INTERIOR <addr-inside-block> <block-addr> <path>     interior pointer held by <path>
 *   READY
 *
 * Path syntax (identical to the tool's rendering): '.' member of an object, '->' member through
 * a pointer, '[i]' element, a run of more than 3 identical steps is written '(->next)*N'.
 *
 * Leaked addresses are kept only XOR-obfuscated so that no live pointer to them remains, and the
 * stacks are scrubbed after printing so no stale copy survives in dead stack frames.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OBF 0xA5A5A5A55A5A5A5AULL
#define NWORKERS 4
#define NSMALL 96

struct entry_meta { long stamp; void *opaque; };
struct entry { int key; char *data; struct entry_meta *meta; };
struct cache { int count; struct entry entries[8]; };
struct node { int value; struct node *next; void *payload; };
struct item { char *name; int *values; double weight; };
struct worker_state { char *label; void *blocks[6]; uintptr_t leak_obf; };
struct hidden { long tag; char *inner; };

struct cache g_cache;
struct node *g_list;
struct node *g_cycle;
struct item *g_items;
int g_item_count;
char *g_buffer;
void *g_small[NSMALL];
double **g_matrix;
unsigned char *g_big;
char *g_interior;
void *g_opaque_holder;
struct worker_state g_workers[NWORKERS];
static char *s_static_owned;
uintptr_t g_main_leak_obf[3];
uintptr_t g_local_obf[2];
uintptr_t g_freed_obf[32];
size_t g_freed_size[32];
int g_nfreed;

static pthread_barrier_t g_barrier;

static void __attribute__((noinline)) scrub_stack(void)
{
    volatile char pad[65536];
    memset((char *)pad, 0, sizeof(pad));
}

static void record_freed(void *p, size_t sz)
{
    g_freed_obf[g_nfreed] = (uintptr_t)p ^ OBF;
    g_freed_size[g_nfreed] = sz;
    g_nfreed++;
}

static void *__attribute__((noinline)) make_leak(size_t sz)
{
    void *p = malloc(sz);
    memset(p, 0x11, sz);
    return (void *)((uintptr_t)p ^ OBF);
}

static void *worker_main(void *arg)
{
    int idx = (int)(intptr_t)arg;
    char nm[16];
    snprintf(nm, sizeof(nm), "worker%d", idx);
    pthread_setname_np(pthread_self(), nm);
    struct worker_state *w = &g_workers[idx];
    w->label = malloc(16 + idx);
    snprintf(w->label, 16, "w%d", idx);
    for (int k = 0; k < 6; k++) {
        w->blocks[k] = malloc(24 + 40 * k + idx);
        memset(w->blocks[k], 0x22, 24 + 40 * k + idx);
    }
    /* per-thread tcache + thread-arena fastbin: free 9 blocks of the same size class */
    void *tmp[9];
    for (int k = 0; k < 9; k++)
        tmp[k] = malloc(40);
    for (int k = 0; k < 9; k++)
        free(tmp[k]);
    memset(tmp, 0, sizeof(tmp));
    w->leak_obf = (uintptr_t)make_leak(70 + idx);
    scrub_stack();
    pthread_barrier_wait(&g_barrier);
    for (;;)
        pause();
    return NULL;
}

static void *__attribute__((noinline)) holder_main(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "holder");
    char *only_local = malloc(333);
    memset(only_local, 0x33, 333);
    g_local_obf[0] = (uintptr_t)only_local ^ OBF;
    pthread_barrier_wait(&g_barrier);
    for (;;)
        pause();
    return only_local;
}

static void print_path_list(char *buf, size_t n, int k)
{
    if (k == 0)
        snprintf(buf, n, "g_list");
    else if (k <= 3) {
        size_t o = (size_t)snprintf(buf, n, "g_list");
        for (int i = 0; i < k; i++)
            o += (size_t)snprintf(buf + o, n - o, "->next");
    } else
        snprintf(buf, n, "g_list(->next)*%d", k);
}

int main(void)
{
    char path[256];
    pthread_setname_np(pthread_self(), "fixture_main");
    setvbuf(stdout, NULL, _IOFBF, 1 << 16);

    /* globals: struct with an array of structs with pointer members */
    g_cache.count = 8;
    for (int i = 0; i < 8; i++) {
        g_cache.entries[i].key = i;
        g_cache.entries[i].data = malloc(32 + 16 * i);
        memset(g_cache.entries[i].data, 'a' + i, 32 + 16 * i);
        if (i % 2 == 0) {
            g_cache.entries[i].meta = malloc(sizeof(struct entry_meta));
            g_cache.entries[i].meta->stamp = i;
            g_cache.entries[i].meta->opaque = malloc(56);
            memset(g_cache.entries[i].meta->opaque, 0x44, 56);
        }
    }
    /* linked list (50 nodes, each with a payload) */
    struct node **tail = &g_list;
    for (int k = 0; k < 50; k++) {
        struct node *n = malloc(sizeof(*n));
        n->value = k;
        n->next = NULL;
        n->payload = malloc(48);
        memset(n->payload, 0x55, 48);
        *tail = n;
        tail = &n->next;
    }
    /* 2-node cycle */
    g_cycle = malloc(sizeof(struct node));
    g_cycle->next = malloc(sizeof(struct node));
    g_cycle->next->next = g_cycle;
    g_cycle->payload = g_cycle->next->payload = NULL;
    /* array of structs with pointer members */
    g_item_count = 16;
    g_items = malloc(g_item_count * sizeof(struct item));
    for (int i = 0; i < g_item_count; i++) {
        g_items[i].name = malloc(10 + i);
        snprintf(g_items[i].name, 10 + i, "item%d", i);
        g_items[i].values = malloc(sizeof(int) * (4 + i));
        g_items[i].weight = i * 0.5;
    }
    /* many small allocations of several size classes */
    static const size_t classes[] = {8, 24, 40, 100, 250, 600, 1500};
    for (int i = 0; i < NSMALL - 1; i++) { /* last slot is filled with the guard block below */
        size_t sz = classes[i % 7];
        g_small[i] = malloc(sz);
        memset(g_small[i], 0x66, sz);
    }
    /* pointer-to-pointer */
    g_matrix = malloc(5 * sizeof(double *));
    for (int r = 0; r < 5; r++)
        g_matrix[r] = calloc(7, sizeof(double));
    g_buffer = malloc(100);
    memset(g_buffer, 'b', 100);
    s_static_owned = malloc(144);
    memset(s_static_owned, 's', 144);
    /* large (mmapped) allocation */
    g_big = malloc(2 * 1024 * 1024);
    memset(g_big, 0x77, 4096);
    /* interior pointer */
    char *interior_block = malloc(160);
    memset(interior_block, 0x12, 160);
    g_interior = interior_block + 40;
    interior_block = NULL;
    /* untyped holder: g_opaque_holder (void*) -> struct hidden -> inner */
    struct hidden *h = malloc(sizeof(*h));
    h->tag = 7;
    h->inner = malloc(90);
    memset(h->inner, 0x13, 90);
    g_opaque_holder = h;
    /* true leaks: the pointer is erased */
    g_main_leak_obf[0] = (uintptr_t)make_leak(200);
    g_main_leak_obf[1] = (uintptr_t)make_leak(64);
    g_main_leak_obf[2] = (uintptr_t)make_leak(5000);

    pthread_barrier_init(&g_barrier, NULL, NWORKERS + 2);
    pthread_t th[NWORKERS + 1];
    for (int i = 0; i < NWORKERS; i++)
        pthread_create(&th[i], NULL, worker_main, (void *)(intptr_t)i);
    pthread_create(&th[NWORKERS], NULL, holder_main, NULL);
    pthread_barrier_wait(&g_barrier);
    /* allocate the stdio buffer now so that printing below does not reuse freed blocks */
    printf("START\n");
    fflush(stdout);
    /* freed blocks: tcache, fastbin overflow (> 7 of one class) and a small-bin sized block */
    void *f[12];
    for (int k = 0; k < 10; k++)
        f[k] = malloc(56);
    f[10] = malloc(1200);
    void *guard = malloc(32); /* keep the 1200-byte block away from top */
    g_small[NSMALL - 1] = guard;
    f[11] = malloc(300);
    for (int k = 0; k < 10; k++) {
        record_freed(f[k], 56);
        free(f[k]);
    }
    record_freed(f[10], 1200);
    free(f[10]);
    record_freed(f[11], 300);
    free(f[11]);
    memset(f, 0, sizeof(f));

    /* ------------------------------ ground truth ------------------------------ */
    for (int i = 0; i < 8; i++) {
        printf("BLOCK %p %d g_cache.entries[%d].data\n", (void *)g_cache.entries[i].data, 32 + 16 * i, i);
        if (g_cache.entries[i].meta) {
            printf("BLOCK %p %zu g_cache.entries[%d].meta\n", (void *)g_cache.entries[i].meta, sizeof(struct entry_meta), i);
            printf("BLOCK %p 56 g_cache.entries[%d].meta->opaque\n", g_cache.entries[i].meta->opaque, i);
        }
    }
    struct node *n = g_list;
    for (int k = 0; n; k++, n = n->next) {
        print_path_list(path, sizeof(path), k);
        printf("BLOCK %p %zu %s\n", (void *)n, sizeof(*n), path);
        printf("BLOCK %p 48 %s->payload\n", n->payload, path);
    }
    printf("BLOCK %p %zu g_cycle\n", (void *)g_cycle, sizeof(struct node));
    printf("BLOCK %p %zu g_cycle->next\n", (void *)g_cycle->next, sizeof(struct node));
    printf("BLOCK %p %zu g_items\n", (void *)g_items, g_item_count * sizeof(struct item));
    for (int i = 0; i < g_item_count; i++) {
        printf("BLOCK %p %d g_items[%d].name\n", (void *)g_items[i].name, 10 + i, i);
        printf("BLOCK %p %zu g_items[%d].values\n", (void *)g_items[i].values, sizeof(int) * (4 + i), i);
    }
    for (int i = 0; i < NSMALL - 1; i++)
        printf("BLOCK %p %zu g_small[%d]\n", g_small[i], classes[i % 7], i);
    printf("BLOCK %p 32 g_small[%d]\n", g_small[NSMALL - 1], NSMALL - 1);
    printf("BLOCK %p %zu g_matrix\n", (void *)g_matrix, 5 * sizeof(double *));
    for (int r = 0; r < 5; r++)
        printf("BLOCK %p %zu g_matrix[%d]\n", (void *)g_matrix[r], 7 * sizeof(double), r);
    printf("BLOCK %p 100 g_buffer\n", (void *)g_buffer);
    printf("BLOCK %p 144 s_static_owned\n", (void *)s_static_owned);
    printf("BLOCK %p %d g_big\n", (void *)g_big, 2 * 1024 * 1024);
    printf("INTERIOR %p %p g_interior\n", (void *)g_interior, (void *)(g_interior - 40));
    printf("BLOCK %p %zu g_opaque_holder\n", g_opaque_holder, sizeof(struct hidden));
    printf("OPAQUE %p 90 g_opaque_holder\n", (void *)((struct hidden *)g_opaque_holder)->inner);
    for (int i = 0; i < NWORKERS; i++) {
        printf("BLOCK %p %d g_workers[%d].label\n", (void *)g_workers[i].label, 16 + i, i);
        for (int k = 0; k < 6; k++)
            printf("BLOCK %p %d g_workers[%d].blocks[%d]\n", g_workers[i].blocks[k], 24 + 40 * k + i, i, k);
        printf("LEAK 0x%lx %d\n", (unsigned long)(g_workers[i].leak_obf ^ OBF), 70 + i);
    }
    printf("LOCAL 0x%lx 333 holder holder_main only_local\n", (unsigned long)(g_local_obf[0] ^ OBF));
    printf("LEAK 0x%lx 200\n", (unsigned long)(g_main_leak_obf[0] ^ OBF));
    printf("LEAK 0x%lx 64\n", (unsigned long)(g_main_leak_obf[1] ^ OBF));
    printf("LEAK 0x%lx 5000\n", (unsigned long)(g_main_leak_obf[2] ^ OBF));
    for (int k = 0; k < g_nfreed; k++)
        printf("FREED 0x%lx %zu\n", (unsigned long)(g_freed_obf[k] ^ OBF), g_freed_size[k]);
    printf("READY\n");
    fflush(stdout);
    n = NULL;
    h = NULL;
    guard = NULL;
    scrub_stack();
    for (;;)
        pause();
    return 0;
}
