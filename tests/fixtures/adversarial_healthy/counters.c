#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* balanced malloc/free; statistics named like alloc/free counters but unrelated */
long alloc_total; long free_slots = 5; long malloc_threshold = 131072; long release_version = 3;
struct Stat { long allocations; long freelist_len; long reclaim_interval; } g_stat = { 0, 2, 30 };
int main(void){ printf("READY\n"); fflush(stdout);
  for(;;){ void *p = malloc(256); alloc_total++; g_stat.allocations++; free(p); usleep(1000); } }
