/*
 * Real Native Linux Process Fixture: Mapping Growth Without RSS Growth
 * Creates 64MB of anonymous virtual memory via mmap after baseline sample.
 * Proves that virtual mapping expansion (VSZ) does NOT equal allocation or physical RAM (RSS).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>

static volatile sig_atomic_t g_running = 1;

static void handle_sigterm(int sig) {
    (void)sig;
    g_running = 0;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    printf("[PROC_VSZ_ONLY] PID %d started\n", getpid());
    fflush(stdout);

    // Initial baseline window: allow sample 0 to record pre-mmap metrics
    usleep(25000);

    // Allocate 64MB virtual mapping without touching pages
    size_t map_sz = 64 * 1024 * 1024;
    void *addr = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    printf("[PROC_VSZ_ONLY] Mapped %zu bytes at %p\n", map_sz, addr);
    fflush(stdout);

    while (g_running) {
        usleep(50000);
    }

    munmap(addr, map_sz);
    return 0;
}
