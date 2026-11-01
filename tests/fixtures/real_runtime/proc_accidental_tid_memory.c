/*
 * proc_accidental_tid_memory.c
 * Accidental TID Match Adversarial Fixture.
 * Phase 2.0-A.3.4 Adversarial Runtime Fixture.
 *
 * Demonstrates a non-mutex memory buffer containing an integer equal to
 * an active thread TID at offset 8, but with invalid kind/lock state.
 * The inspection engine MUST reject this coincidental TID match as MUTEX_STATE_INVALID.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <pthread.h>

#pragma pack(push, 4)
typedef struct {
    int32_t lock_word;      /* offset 0: 0 or non-standard */
    uint32_t count;         /* offset 4: 99999 (invalid for normal mutex) */
    int32_t coincidental_tid; /* offset 8: populated with thread TID */
    uint32_t nusers;        /* offset 12: 0 */
    int32_t invalid_kind;   /* offset 16: 0xdeadbeef (invalid kind flags) */
    uint8_t padding[28];
} fake_mutex_buffer_t;
#pragma pack(pop)

static volatile sig_atomic_t g_running = 1;
static fake_mutex_buffer_t g_fake_buffer;

static void handle_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

static void *worker_fn(void *arg) {
    (void)arg;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    g_fake_buffer.lock_word = 1;
    g_fake_buffer.count = 99999;
    g_fake_buffer.coincidental_tid = tid;
    g_fake_buffer.nusers = 0;
    g_fake_buffer.invalid_kind = 0xdeadbeef; /* invalid flags */

    while (g_running) {
        usleep(10000);
    }
    return NULL;
}

int main(void) {
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT, handle_sigterm);

    pthread_t th;
    if (pthread_create(&th, NULL, worker_fn, NULL) != 0) {
        perror("pthread_create");
        return 1;
    }

    usleep(20000);

    printf("[FAKE_MUTEX] PID %d running (fake_addr=%p, tid=%d)\n",
           getpid(), (void *)&g_fake_buffer, g_fake_buffer.coincidental_tid);
    fflush(stdout);

    while (g_running) {
        pause();
    }

    pthread_join(th, NULL);
    return 0;
}
