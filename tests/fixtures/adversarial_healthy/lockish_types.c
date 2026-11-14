/* Healthy, idle.  Types whose NAMES contain "lock" as a substring but are not locks (clock_t, struct block_stats)
 * with non-zero first words, and struct members named like lock words / owners (block_count, owner_ref). */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
typedef struct block_stats { uint32_t block_size; int block_count; int owner_ref; int tid_hint; } block_stats_t;
clock_t g_last_clock = 12345;
block_stats_t g_blk = { 4096, 7, 99999, 4242 };
struct block_stats g_blocks_seen = { 512, 3, 77777, 1 };
pthread_mutex_t g_real_mutex = PTHREAD_MUTEX_INITIALIZER;
int main(void) { g_last_clock = clock() + 12345; printf("READY\n"); fflush(stdout); for (;;) pause(); }
