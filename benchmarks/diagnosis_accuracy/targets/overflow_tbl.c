/* Minimal string-keyed table; slots are allocated one after another. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct slot {
    char key[16];
    long val;
};

static struct slot *tbl[4];

static void tbl_put(int i, const char *key, long val)
{
    tbl[i] = malloc(sizeof(struct slot));
    strcpy(tbl[i]->key, key);
    tbl[i]->val = val;
}

int main(void)
{
    tbl_put(0, "alpha", 1);
    tbl_put(1, "beta", 2);
    tbl_put(2, "gamma", 3);
    tbl_put(3, "a_rather_long_key_name_from_config_file_x", 4);
    write(1, "READY\n", 6);
    for (;;)
        pause();
}
