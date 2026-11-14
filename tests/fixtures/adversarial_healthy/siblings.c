/* Healthy and idle.  Magic fields in arrays of objects: two VALID states (live / released, each on several
 * elements) and unused zero slots - sibling elements disagree, but no single element is the odd one out.  A guard
 * global and a cookie array hold poison-looking constants that are this program's valid values. */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#define LIVE 0xDEADBEEFu
#define RELEASED 0xBAADF00Du
struct Slot { uint32_t magic; int refcnt; char name[8]; };
struct Slot g_slots[8] = { {LIVE, 1, "a"}, {RELEASED, 0, ""}, {LIVE, 2, "b"}, {RELEASED, 0, ""},
                           {LIVE, 1, "c"}, {RELEASED, 0, ""}, {0, 0, ""}, {0, 0, ""} };
struct Node { uint64_t cookie; int id; };
struct Node g_nodes[5] = { {0xDEADBEEFDEADBEEFull, 1}, {0xDEADBEEFDEADBEEFull, 2}, {0xDEADBEEFDEADBEEFull, 3},
                           {0xDEADBEEFDEADBEEFull, 4}, {0xDEADBEEFDEADBEEFull, 5} };
uint32_t g_guard = 0xDEADBEEFu;
uint32_t stack_canary_copy = 0xBAADBAADu;
int main(void) { printf("READY\n"); fflush(stdout); for (;;) pause(); }
