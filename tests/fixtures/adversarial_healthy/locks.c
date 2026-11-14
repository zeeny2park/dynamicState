#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
/* integers named like locks; one real, uncontended mutex */
int lock_owner = 1234; int mutex_waiters = 5; long g_lock = 2; int deadlock_count = 1;
struct L { int mutex; int owner; int waiters; } g_fake_mutex = { 2, 4321, 3 };
pthread_mutex_t g_real = PTHREAD_MUTEX_INITIALIZER;
static void *w(void *a){ for(;;){ pthread_mutex_lock(&g_real); pthread_mutex_unlock(&g_real); usleep(20000);} }
int main(void){ pthread_t t; pthread_create(&t,0,w,0); printf("READY\n"); fflush(stdout); for(;;) pause(); }
