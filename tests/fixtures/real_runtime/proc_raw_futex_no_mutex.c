/*
 * proc_raw_futex_no_mutex.c
 * Raw Linux Futex without pthread_mutex_t layout.
 * Phase 2.0-A.3.4 Adversarial Runtime Fixture.
 *
 * Demonstrates a thread blocking on a raw integer futex word (SYS_futex).
 * The memory is a simple uint32_t, NOT a 40/48-byte glibc pthread_mutex_t.
 * The inspection engine MUST NOT fabricate an owner TID or mutex state.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <pthread.h>

static volatile sig_atomic_t g_running = 1;
static uint32_t g_raw_futex_word = 42;

static void handle_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

static void *futex_waiter_thread(void *arg) {
    (void)arg;
    /* Block in raw kernel futex wait on g_raw_futex_word */
    while (g_running) {
        syscall(SYS_futex, &g_raw_futex_word, FUTEX_WAIT, 42, NULL, NULL, 0);
        usleep(10000);
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th;
    if (pthread_create(&th, NULL, futex_waiter_thread, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    /* Print futex word address for test inspection */
    printf("[RAW_FUTEX] PID %d running (futex_addr=%p)\n", getpid(), (void *)&g_raw_futex_word);
    fflush(stdout);

    while (g_running) {
        pause();
    }

    pthread_join(th, NULL);
    return 0;
}
