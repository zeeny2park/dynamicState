/* IMP-009 fixture: global arrays overrun into the next global (built with -fno-toplevel-reorder so the
 * variables are laid out in definition order; the program checks the layout itself and says so).
 *
 *   char g_title[24]; struct item *g_cursor;  strcpy of 31 chars + NUL into g_title -> g_cursor holds text
 *                                              (a pointer into no mapping)
 *   char g_tag[13]; bool g_enabled;            14-byte copy into g_tag -> g_enabled holds 'x' (not 0/1)
 *   char g_note[16]; struct item *g_spare;     intact control pair (g_spare valid)
 *
 * Prints: LAYOUT ok|bad, GLOBAL_OVERRUN <array> <neighbour> (one line per damaged pair), READY.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct item {
    int id;
    long weight;
};

char g_title[24];
struct item *g_cursor;
char g_tag[13];
bool g_enabled;
char g_note[16];
struct item *g_spare;

int main(void)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 14);
    g_cursor = malloc(sizeof *g_cursor);
    g_spare = malloc(sizeof *g_spare);
    g_enabled = true;
    strcpy(g_note, "fine");
    int ok = (char *)&g_cursor == g_title + sizeof g_title && (char *)&g_enabled == g_tag + sizeof g_tag;
    printf("LAYOUT %s\n", ok ? "ok" : "bad");
    printf("GLOBAL_OVERRUN g_title g_cursor\n");
    printf("GLOBAL_OVERRUN g_tag g_enabled\n");
    fflush(stdout);
    /* the bad writes, through a volatile pointer so the compiler neither rejects nor fortifies them */
    char *volatile dst = g_title;
    const char *src = "configuration-name-that-is-long"; /* 31 chars + NUL = 32 bytes into 24 */
    for (size_t i = 0; i <= strlen(src); i++)
        dst[i] = src[i];
    dst = g_tag;
    for (size_t i = 0; i < 14; i++)                      /* 14 bytes into 13 */
        dst[i] = "abcdefghijklmx"[i];
    printf("READY\n");
    fflush(stdout);
    for (;;)
        pause();
}
