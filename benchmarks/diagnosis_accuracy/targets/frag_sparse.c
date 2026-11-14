/* Builds a large table of small records, then drops three of every four and idles. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NREC 80000
#define RECSZ 240

static char *recs[NREC];
static volatile unsigned live;

int main(void)
{
    for (unsigned i = 0; i < NREC; i++) {
        recs[i] = malloc(RECSZ);
        if (recs[i])
            memset(recs[i], (int)(i & 0xff), RECSZ);
    }
    for (unsigned i = 0; i < NREC; i++) {
        if (i % 4) {
            free(recs[i]);
            recs[i] = NULL;
        } else {
            live++;
        }
    }
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
