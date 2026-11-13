/* slot_server: a connection-slot pool for the web UI's exploration features (pool view, watch, value follow).
 *
 * A fixed array of 4096 slots (48 bytes each, 196,608 bytes) lives in .bss; one worker thread moves a few hundred
 * slots between states every second with a deterministic generator, the main thread sleeps.  Nothing is allocated
 * after start-up, so memory stays flat (FIXTURE_CAP: no growth by construction).  Prints READY once the pool is busy.
 * Not a diagnosis benchmark target: it is healthy by design.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NSLOTS 4096

enum slot_state { SLOT_FREE = 0, SLOT_ACCEPTING, SLOT_READING, SLOT_WRITING, SLOT_CLOSING };

struct slot {
    enum slot_state state;
    int fd;
    uint32_t peer_addr;
    uint16_t peer_port;
    uint16_t flags;
    uint64_t rx;
    uint64_t tx;
    uint64_t last_ms;
    uint64_t gen;
};

struct slot g_slots[NSLOTS];
volatile int g_slots_used;
volatile uint64_t g_ticks;
struct slot *g_last;                      /* the slot changed last: a pointer to follow */
static const char g_service[] = "slot_server v1";

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void *churn(void *arg)
{
    (void)arg;
    uint32_t x = 2463534242u;
    pthread_setname_np(pthread_self(), "slot_churn");
    for (;;) {
        for (int k = 0; k < 120; k++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            struct slot *s = &g_slots[x % NSLOTS];
            switch (s->state) {
            case SLOT_FREE:
                if ((x >> 12) % 3 != 0) {
                    s->state = SLOT_ACCEPTING; s->fd = 5 + (int)(x % 1800);
                    s->peer_addr = 0x0a040000u | (x & 0xffffu); s->peer_port = (uint16_t)(40000 + x % 20000);
                    g_slots_used++;
                }
                break;
            case SLOT_ACCEPTING: s->state = SLOT_READING; break;
            case SLOT_READING: s->state = SLOT_WRITING; s->rx += 512 + (x % 97); break;
            case SLOT_WRITING: s->state = (x >> 9) % 8 ? SLOT_READING : SLOT_CLOSING; s->tx += 256 + (x % 61); break;
            case SLOT_CLOSING:
                memset(s, 0, sizeof *s); s->fd = -1; g_slots_used--;
                break;
            }
            s->last_ms = now_ms();
            s->gen++;
            g_last = s;
        }
        g_ticks++;
        usleep(100000);
    }
    return NULL;
}

int main(void)
{
    pthread_t t;
    for (int i = 0; i < NSLOTS; i++)
        g_slots[i].fd = -1;
    pthread_create(&t, NULL, churn, NULL);
    while (g_ticks < 5)
        usleep(20000);
    printf("READY %s\n", g_service);
    fflush(stdout);
    for (;;)
        pause();
}
