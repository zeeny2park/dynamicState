/*
 * IMP-010 fixture: three distinguishable thread behaviours in one process.
 *   spin_hang       : infinite loop, 100% CPU, no syscalls, no progress (function spin_forever)
 *   busy_worker     : ~100% CPU, REAL progress: processes items, hands results to the kernel with
 *                     write() and advances g_items_done (functions process_item / checksum_block)
 *   blocked_reader  : blocks in read(2) on a pipe nobody writes to, for the entire run
 *   cv_idle         : pthread_cond_wait with no timeout and no signaller (idle worker or hung: not distinguishable)
 *   churn_spawner   : creates and joins a short-lived thread (lives ~200 ms) every ~50 ms: threads appear and disappear
 *   thread_leaker   : starts one more blocked thread every ~100 ms (thread count grows)
 * Usage: proc_thread_spin_work_block [s][w][b][c][x][g]   (default "swb"; each letter starts one thread)
 * Prints READY once all requested threads are at steady state.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>

static volatile unsigned long g_spin_counter = 0;
static volatile unsigned long g_items_done = 0;
static int g_pipe[2];
static int g_devnull = -1;

static void on_term(int s) { (void)s; _exit(0); }

__attribute__((noinline)) static void spin_forever(void) {
    for (;;) { g_spin_counter++; }
}

__attribute__((noinline)) static unsigned long checksum_block(unsigned long seed) {
    unsigned long h = seed;
    for (int i = 0; i < 20000; i++) { h = h * 1315423911UL + (unsigned long)i; }
    return h;
}

__attribute__((noinline)) static void process_item(unsigned long n) {
    unsigned long h = checksum_block(n);
    char buf[16];
    memcpy(buf, &h, sizeof h);
    if (write(g_devnull, buf, sizeof h) < 0) { /* ignore */ }
    g_items_done++;
}

static pthread_mutex_t g_cv_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;

static void *cv_thread(void *a) {
    (void)a; prctl(PR_SET_NAME, "cv_idle");
    pthread_mutex_lock(&g_cv_mutex);
    for (;;) pthread_cond_wait(&g_cv, &g_cv_mutex);
    return NULL;
}
static void *short_lived(void *a) { (void)a; prctl(PR_SET_NAME, "ephemeral"); usleep(200000); return NULL; }
static void *churn_thread(void *a) {
    (void)a; prctl(PR_SET_NAME, "churn_spawner");
    for (;;) {
        pthread_t t;
        if (pthread_create(&t, NULL, short_lived, NULL) == 0) pthread_join(t, NULL);
        usleep(50000);
    }
    return NULL;
}
static void *leaked(void *a) { (void)a; prctl(PR_SET_NAME, "leaked_worker"); pause(); return NULL; }
static void *leak_thread(void *a) {
    (void)a; prctl(PR_SET_NAME, "thread_leaker");
    for (;;) {
        pthread_t t;
        if (pthread_create(&t, NULL, leaked, NULL) == 0) pthread_detach(t);
        usleep(100000);
    }
    return NULL;
}

static void *spin_thread(void *a) { (void)a; prctl(PR_SET_NAME, "spin_hang"); spin_forever(); return NULL; }
static void *work_thread(void *a) {
    (void)a; prctl(PR_SET_NAME, "busy_worker");
    for (unsigned long n = 0;; n++) { process_item(n); }
    return NULL;
}
static void *block_thread(void *a) {
    (void)a; prctl(PR_SET_NAME, "blocked_reader");
    char c;
    for (;;) { if (read(g_pipe[0], &c, 1) < 0) { sleep(1); } }
    return NULL;
}

int main(int argc, char **argv) {
    const char *modes = argc > 1 ? argv[1] : "swb";
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    if (pipe(g_pipe) != 0) return 1;
    g_devnull = open("/dev/null", O_WRONLY);
    pthread_t t;
    for (const char *m = modes; *m; m++) {
        void *(*fn)(void *) = *m == 's' ? spin_thread : *m == 'w' ? work_thread : *m == 'b' ? block_thread
                             : *m == 'c' ? cv_thread : *m == 'x' ? churn_thread : *m == 'g' ? leak_thread : NULL;
        if (fn && pthread_create(&t, NULL, fn, NULL) != 0) return 1;
    }
    usleep(300000);
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;) pause();
}
