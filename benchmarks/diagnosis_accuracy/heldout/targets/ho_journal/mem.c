/* Checked allocation helpers shared by the modules. */
#include <stdlib.h>
#include "mem.h"

void *mem_get(size_t n)
{
    void *p = malloc(n);
    if (!p)
        abort();
    return p;
}

void mem_put(void *p)
{
    free(p);
}
