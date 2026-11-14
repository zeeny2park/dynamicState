#ifndef SYNC_H
#define SYNC_H
#include <pthread.h>
void take(pthread_mutex_t *m);
void give(pthread_mutex_t *m);
#endif
