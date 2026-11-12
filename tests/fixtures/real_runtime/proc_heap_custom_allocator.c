/* IMP-007 negative fixture: the program interposes its own malloc/free (bump allocator), so a
 * glibc ptmalloc heap walk does not describe its heap and must be refused. Prints READY, blocks. */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned char g_arena[1 << 20];
static size_t g_used;

void *malloc(size_t n)
{
    n = (n + 15) & ~(size_t)15;
    if (g_used + n > sizeof(g_arena))
        return NULL;
    void *p = g_arena + g_used;
    g_used += n;
    return p;
}

void free(void *p) { (void)p; }

void *calloc(size_t a, size_t b)
{
    void *p = malloc(a * b);
    if (p)
        memset(p, 0, a * b);
    return p;
}

void *realloc(void *p, size_t n)
{
    void *q = malloc(n);
    if (q && p)
        memcpy(q, p, n); /* bump allocator: n bytes after p stay inside g_arena */
    return q;
}

char *g_owned;

int main(void)
{
    g_owned = malloc(100);
    printf("BLOCK %p 100 g_owned\nREADY\n", (void *)g_owned);
    fflush(stdout);
    for (;;)
        pause();
}
