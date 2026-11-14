/* Healthy.  Types whose NAMES contain "lock" but are not mutexes (clock_t, struct flock, struct Blocker,
 * BlockHeader), lock types without the glibc mutex layout (sem_t, pthread_rwlock_t), a struct that starts with a real
 * mutex followed by application fields named owner_tid / lock_count, and threads blocked in futex waits for
 * unrelated reasons (a condition variable, a semaphore, a read lock held by a sleeping thread). */
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
typedef struct block_stats { uint32_t block_size; int block_count; int owner_ref; int tid_hint; } block_stats_t;
struct Blocker { int held_count; int owner_uid; long tid_base; };
typedef struct Blocker BlockHeader;
struct guarded { pthread_mutex_t mu; int owner_tid; int lock_count; };
clock_t g_last_clock = 12345;
block_stats_t g_blk = { 4096, 7, 99999, 4242 };
struct flock g_fl = { F_WRLCK, SEEK_SET, 0, 0, 77777 };
struct Blocker g_blocker = { 3, 1000, 4242 };
BlockHeader g_block_header = { 2, 99998, 31337 };
struct guarded g_guarded = { PTHREAD_MUTEX_INITIALIZER, 99997, 3 };
sem_t g_sem_avail;
sem_t g_sem_wait;
pthread_rwlock_t g_rw = PTHREAD_RWLOCK_INITIALIZER;
pthread_mutex_t g_cv_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
int g_go = 0;
static void *cv_waiter(void *a) {
    (void)a;
    pthread_mutex_lock(&g_cv_mu);
    while (!g_go) pthread_cond_wait(&g_cv, &g_cv_mu);
    pthread_mutex_unlock(&g_cv_mu);
    return 0;
}
static void *sem_waiter(void *a) { (void)a; sem_wait(&g_sem_wait); return 0; }
static void *reader(void *a) { (void)a; pthread_rwlock_rdlock(&g_rw); for (;;) pause(); return 0; }
int main(void) {
    pthread_t t1, t2, t3;
    sem_init(&g_sem_avail, 0, 5);
    sem_init(&g_sem_wait, 0, 0);
    g_last_clock = clock() + 12345;
    pthread_create(&t1, 0, cv_waiter, 0);
    pthread_create(&t2, 0, sem_waiter, 0);
    pthread_create(&t3, 0, reader, 0);
    usleep(100000);
    printf("READY\n"); fflush(stdout);
    for (;;) pause();
}
