#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
/* 0xDEADBEEF is this program's VALID magic */
#define MAGIC 0xDEADBEEFu
uint32_t g_magic = MAGIC; uint32_t g_canary = 0xBAADF00Du;
struct Hdr { uint32_t magic; uint32_t stage; uint32_t header_crc; uint32_t tag; } g_hdr = { MAGIC, 0xDEADDEADu, MAGIC, MAGIC };
struct Hdr *g_hdr_p = &g_hdr;
int main(void){ printf("READY\n"); fflush(stdout); for(;;) pause(); }
