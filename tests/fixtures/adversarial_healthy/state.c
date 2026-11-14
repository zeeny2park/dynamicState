#include <stdio.h>
#include <unistd.h>
int heartbeat = 7; int g_mode = 250; int g_status = -1; int error_step = 999; int phase_count = 100000;
enum Color { RED, GREEN } g_color = GREEN;
struct S { int state; int status_code; } g_s = { 1000, -22 };
int main(void){ printf("READY\n"); fflush(stdout); for(;;) pause(); }
