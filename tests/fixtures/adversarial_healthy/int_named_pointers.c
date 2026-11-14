/* Healthy, idle (from tests/test_integer_member_not_a_pointer.py): integer members named like pointers ("buf",
 * "ptr", "addr", "payload", "cache", "record") with small values that would land in the NULL page. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct Stats {
    int32_t total_buffers;      /* 32 */
    int32_t ptr_count;          /* 7 */
    uint16_t addr_family;       /* 2 */
    int32_t payload_len;        /* 100 */
    int64_t cache_hits;         /* 4000 */
    int32_t record_count;       /* 12 */
    char *name;                 /* a real, valid pointer */
};
struct Stats g_stats;
struct Stats *g_stats_ptr = &g_stats;
int main(void) {
    g_stats.total_buffers = 32; g_stats.ptr_count = 7; g_stats.addr_family = 2; g_stats.payload_len = 100;
    g_stats.cache_hits = 4000; g_stats.record_count = 12; g_stats.name = malloc(64);
    printf("READY\n"); fflush(stdout);
    for (;;) pause();
}
