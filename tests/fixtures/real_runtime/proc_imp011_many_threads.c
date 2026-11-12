/*
 * IMP-011 fixture: a process with many blocked threads (remote thread information).
 *   usage: proc_imp011_many_threads <N> [x]
 *   N worker threads named "w00".."wNN" block in read(2) on a pipe nobody writes to;
 *   one more thread is named with spaces and parentheses ("we ird)(na me") and blocks in read(2) too;
 *   with "x" a churn thread creates and joins a short-lived thread every ~2 ms (threads vanish while a
 *   collector enumerates /proc/PID/task).
 * Prints READY once all threads exist.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>

static int g_pipe[2];
static const char *WEIRD_NAME = "we ird)(na me";

static void on_term(int s) { (void)s; _exit(0); }

__attribute__((noinline)) static void wait_for_data(void) {
    char c;
    for (;;) { if (read(g_pipe[0], &c, 1) < 0) sleep(1); }
}

static void *worker(void *a) {
    char name[16];
    long i = (long)a;
    if (i < 0) snprintf(name, sizeof name, "%s", WEIRD_NAME);
    else snprintf(name, sizeof name, "w%02d", (int)(i % 100));
    prctl(PR_SET_NAME, name);
    wait_for_data();
    return NULL;
}

static void *blip(void *a) { (void)a; prctl(PR_SET_NAME, "blip"); return NULL; }
static void *churn(void *a) {
    (void)a; prctl(PR_SET_NAME, "churn");
    for (;;) {
        pthread_t t;
        if (pthread_create(&t, NULL, blip, NULL) == 0) pthread_join(t, NULL);
        usleep(2000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 4;
    signal(SIGTERM, on_term);
    if (pipe(g_pipe) != 0) return 1;
    pthread_t t;
    for (long i = 0; i < n; i++) if (pthread_create(&t, NULL, worker, (void *)i) != 0) return 1;
    if (pthread_create(&t, NULL, worker, (void *)-1L) != 0) return 1;
    if (argc > 2 && argv[2][0] == 'x' && pthread_create(&t, NULL, churn, NULL) != 0) return 1;
    usleep(300000);
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;) pause();
}
