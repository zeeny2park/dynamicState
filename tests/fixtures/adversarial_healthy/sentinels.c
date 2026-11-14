/* Healthy and idle.  State-like integers hold sentinel values that are VALID in this program:
 * -1 = "not configured", all-ones = "every subsystem up", INT_MAX = "never".  A value alone is not an anomaly
 * without an expected range. */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
int g_mode = -1;
unsigned int g_status = 0xFFFFFFFFu;
long g_phase = 0x7FFFFFFF;
enum Step { STEP_IDLE, STEP_RUN } g_step = STEP_IDLE;
uint64_t heartbeat_ns = 0xFFFFFFFFFFFFFFFFull;
struct Conn { int fd; int state; unsigned int retry_mode; } g_conn = { -1, -1, 0xFFFFFFFFu };
int main(void) { printf("READY\n"); fflush(stdout); for (;;) pause(); }
