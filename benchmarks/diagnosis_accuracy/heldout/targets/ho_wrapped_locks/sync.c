/* Checked lock helpers. */
#include <stdlib.h>
#include "sync.h"

void take(pthread_mutex_t *m)
{
    if (pthread_mutex_lock(m) != 0)
        abort();
}

void give(pthread_mutex_t *m)
{
    if (pthread_mutex_unlock(m) != 0)
        abort();
}
