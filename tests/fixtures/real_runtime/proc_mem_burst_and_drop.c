/*
 * Real Native Linux Process Fixture: Temporary Allocation Burst and Drop
 * Demonstrates temporary workload buffering where RSS surges and then drops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <malloc.h>

static volatile sig_atomic_t g_running = 1;

static void handle_sigterm(int sig) {
    (void)sig;
    g_running = 0;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    printf("[PROC_BURST_DROP] PID %d started\n", getpid());
    fflush(stdout);

    // Initial baseline window: allow sample 0 to record pre-burst state
    usleep(20000);

    // Burst: allocate 8MB and dirty all pages
    size_t burst_sz = 8 * 1024 * 1024;
    char *buf = (char *)malloc(burst_sz);
    if (buf) {
        memset(buf, 0x42, burst_sz);
    }

    // Keep burst resident for sample 1
    usleep(35000);

    // Drop: free and trim back to OS
    if (buf) {
        free(buf);
        buf = NULL;
    }
#if defined(__GLIBC__)
    malloc_trim(0);
#endif

    // Run in low memory baseline until termination
    while (g_running) {
        usleep(50000);
    }

    return 0;
}
