#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* steady memory; counters named like containers that only ever increase (statistics) */
struct Pool { int size; int count; void *base; } g_buffer_pool = { 4096, 0, 0 };
long cache_lookups; long retained_total; long leak_checks_done;
struct V { long vector_ops; long pool_hits; void *p; long n; } g_v;
int main(void){ g_buffer_pool.base = malloc(4096); g_v.p = g_buffer_pool.base; printf("READY\n"); fflush(stdout);
  for(;;){ cache_lookups+=10; retained_total+=3; leak_checks_done++; g_buffer_pool.count++; g_v.vector_ops++; g_v.pool_hits+=2; g_v.n+=5; usleep(1000); } }
