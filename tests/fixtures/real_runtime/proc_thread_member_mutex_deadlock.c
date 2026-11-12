/*
 * IMP-010 fixture: circular deadlock through mutexes that are MEMBERS of global structs.
 *   xfer_ab holds g_acct_a.guard and waits for g_acct_b.guard
 *   xfer_ba holds g_acct_b.guard and waits for g_acct_a.guard
 * Neither variable name nor type name looks like a lock, so only member-level discovery finds them.
 * Prints READY once both threads are blocked.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/prctl.h>

struct account {
    pthread_mutex_t guard;
    long balance;
};

static struct account g_acct_a = { PTHREAD_MUTEX_INITIALIZER, 100 };
static struct account g_acct_b = { PTHREAD_MUTEX_INITIALIZER, 200 };
static volatile int g_hold = 0;

static void on_term(int s) { (void)s; _exit(0); }

static void *xfer_ab(void *a) {
    (void)a; prctl(PR_SET_NAME, "xfer_ab");
    pthread_mutex_lock(&g_acct_a.guard);
    __sync_fetch_and_add(&g_hold, 1);
    while (g_hold < 2) usleep(1000);
    pthread_mutex_lock(&g_acct_b.guard);
    return NULL;
}
static void *xfer_ba(void *a) {
    (void)a; prctl(PR_SET_NAME, "xfer_ba");
    pthread_mutex_lock(&g_acct_b.guard);
    __sync_fetch_and_add(&g_hold, 1);
    while (g_hold < 2) usleep(1000);
    pthread_mutex_lock(&g_acct_a.guard);
    return NULL;
}

int main(void) {
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    pthread_t t1, t2;
    if (pthread_create(&t1, NULL, xfer_ab, NULL) || pthread_create(&t2, NULL, xfer_ba, NULL)) return 1;
    usleep(400000);
    printf("READY pid=%d\n", getpid());
    fflush(stdout);
    for (;;) pause();
}
