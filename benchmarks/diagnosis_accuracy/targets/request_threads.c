#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>

#define MAX_HANDLERS 300

static void *handle_request(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "req_handler");
    for (;;)
        sleep(60);
    return NULL;
}

static void dispatch(int n)
{
    pthread_t t;
    pthread_attr_t at;

    (void)n;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &at, handle_request, NULL);
    pthread_attr_destroy(&at);
}

int main(void)
{
    for (int n = 0; n < 8; n++)
        dispatch(n);
    usleep(1000000);
    write(1, "READY\n", 6);
    for (int n = 8; n < MAX_HANDLERS; n++) {
        usleep(100000);
        dispatch(n);
    }
    for (;;)
        pause();
}
