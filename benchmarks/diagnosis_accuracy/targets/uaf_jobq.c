/* Tiny job queue; a worker finishes the current job and records statistics. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct job {
    struct job *next;
    int id;
    int state;
    char tag[32];
    long runs;
};

static struct job *q_head;
static struct job *cur;

static void q_push(int id)
{
    struct job *j = calloc(1, sizeof *j);
    j->id = id;
    j->next = q_head;
    q_head = j;
}

static struct job *q_pop(void)
{
    struct job *j = q_head;
    if (j)
        q_head = j->next;
    return j;
}

static void job_finish(void)
{
    cur->state = 2;
    free(cur);
    cur->runs++;
}

int main(void)
{
    q_push(1);
    q_push(2);
    cur = q_pop();
    job_finish();
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
