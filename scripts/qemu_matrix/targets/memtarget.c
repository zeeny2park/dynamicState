/* IMP-014 matrix target: a process holding known memory.
 * Prints, on one line, its pid, the address/length of a static buffer and of a 3-page mmap region
 * (byte i = (i*7+3) & 0xff) so the host can verify slice reads, including unaligned and page-crossing ranges. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE 4096
static char g_known[48] = "DYNAMICSTATE-MATRIX-KNOWN-BUFFER-0123456789abcd";

int main(void) {
    unsigned char *r = mmap(NULL, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (r == MAP_FAILED) { perror("mmap"); return 1; }
    for (int i = 0; i < 3 * PAGE; i++) r[i] = (unsigned char)((i * 7 + 3) & 0xff);
    printf("[MEMTARGET] pid=%d known=0x%lx len=%zu region=0x%lx rlen=%d\n",
           (int)getpid(), (unsigned long)(void *)g_known, sizeof(g_known), (unsigned long)(void *)r, 3 * PAGE);
    fflush(stdout);
    for (;;) pause();
    return 0;
}
