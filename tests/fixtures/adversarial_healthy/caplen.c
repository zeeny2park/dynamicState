#include <stdio.h>
#include <unistd.h>
/* unrelated globals: a retry limit and a file size */
int max_retries = 3; long file_size = 100000; int limit_per_user = 2; int name_len = 40; int silent = 9;
struct Conf { int max_fd; long byte_count; int limit; int payload_length; } g_conf = { 4, 5000, 1, 1500 };
int main(void){ printf("READY\n"); fflush(stdout); for(;;) pause(); }
