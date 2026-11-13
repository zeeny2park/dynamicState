/* Request buffers with a small spare pool; a finished request is released, and the cleanup releases it again. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SPARES 7

struct req {
    int id;
    int state;
    char buf[236];
};

static struct req *spare[SPARES];
static struct req *current;

static void spares_fill(void)
{
    for (int i = 0; i < SPARES; i++) {
        spare[i] = malloc(sizeof(struct req));
        memset(spare[i], 0, sizeof(struct req));
    }
}

static void spares_drop(void)
{
    for (int i = 0; i < SPARES; i++) {
        free(spare[i]);
        spare[i] = NULL;
    }
}

static void request_finish(struct req *r)
{
    r->state = 2;
    free(r);
}

static void request_cleanup(void)
{
    if (current)
        free(current);
}

int main(void)
{
    current = calloc(1, sizeof *current);
    current->id = 1;
    spares_fill();
    spares_drop();
    request_finish(current);
    spares_fill();
    request_cleanup();
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
