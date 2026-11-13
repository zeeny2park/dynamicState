/* hostile_strings: a target whose own strings are markup, for the web UI's escaping tests (tests/test_web_explore.py).
 *
 * Thread names, string globals, a struct with a char array and an open file whose path are HTML / script fragments.
 * Every one of them reaches the exploration fragments (thread rows and stacks, variable search, values read from
 * memory, the range view's text column, the open-file list); none may come out as markup.  Bounded: nothing grows.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct note { int id; char text[48]; };

char g_evil[64] = "<script>alert(1)</script><img src=x onerror=alert(2)>";
const char *g_evil_ptr = "\"><svg onload=alert(3)>javascript:alert(4)";
struct note g_note = { 7, "<b onmouseover=alert(5)>x</b>&amp;" };
volatile unsigned long g_count;

static void *spin(void *arg)
{
    (void)arg;
    pthread_setname_np(pthread_self(), "<img src=x>");
    for (;;) {
        g_count++;
        usleep(20000);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t t;
    int fd = -1;
    if (argc > 1)
        fd = open(argv[1], O_RDONLY | O_CREAT, 0600);   /* a path with markup in it, kept open */
    (void)fd;
    pthread_create(&t, NULL, spin, NULL);
    pthread_setname_np(pthread_self(), "<script>");
    while (g_count < 3)
        usleep(10000);
    printf("READY %d\n", (int)strlen(g_evil));
    fflush(stdout);
    for (;;)
        pause();
}
