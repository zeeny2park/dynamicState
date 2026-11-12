/* Use-after-free fixture: a write through a dangling global at offset 0 of a freed tcache chunk - it lands on
 * the tcache next pointer (safe-linked on glibc >= 2.32), which IMP-009 sees as free-list damage.  The chunk's
 * own header is intact (no overflow).  Done once; no malloc/free afterwards (the damaged bin is never used).
 *
 *   g_stale_job = calloc(40) (chunk 48), g_keep = calloc(40), free(g_stale_job), g_stale_job->id = 0x41..41
 * Prints: UAFMETA g_stale_job <freed user addr> 48, then READY.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct job {
    long id;
    long prio;
    char name[24];
};

struct job *g_stale_job;
struct job *g_keep;

int main(void)
{
    static char obuf[4096];
    setvbuf(stdout, obuf, _IOFBF, sizeof obuf);
    g_stale_job = calloc(1, sizeof *g_stale_job);
    g_keep = calloc(1, sizeof *g_keep);
    printf("UAFMETA g_stale_job %p 48\n", (void *)g_stale_job);
    free(g_stale_job);
    g_stale_job->id = 0x4141414141414141L;   /* use after free: overwrites the tcache next pointer */
    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
