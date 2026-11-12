/* Force-included into the IMP-011 remote-thread fixtures: lets a collector that is not an ancestor of the
 * fixture read its /proc/PID/task/TID/syscall and memory under Yama ptrace_scope=1 (CI default). */
#include <sys/prctl.h>
__attribute__((constructor)) static void imp011_allow_any_tracer(void) {
    prctl(0x59616d61 /* PR_SET_PTRACER */, (unsigned long)-1 /* PR_SET_PTRACER_ANY */, 0, 0, 0);
}
