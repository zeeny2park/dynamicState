#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <unistd.h>
#include <signal.h>

// Phase 1 eBPF Stack-Variable Tracing Fixture
// Contains:
// 1. Stack-allocated struct with scalar and array fields
// 2. Local character buffer
// 3. Nested function call
// 4. Non-inlined target function with scalar arguments and local variables
// 5. Test synchronization markers and signal handlers

struct SensorReading {
    uint32_t sensor_id;
    int32_t status_code;
    double calibration_factor;
    uint16_t sample_counts[4]; // Array field
};

static volatile sig_atomic_t g_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

// 3. Nested function called from the traced function
__attribute__((noinline))
int32_t compute_inner_metric(int32_t base, int32_t multiplier, const char* tag) {
    int32_t tag_len = tag ? static_cast<int32_t>(strlen(tag)) : 0;
    return (base * multiplier) + tag_len;
}

// 1, 2, 4. Non-inlined function with scalar args, stack-allocated struct, local buffer, local variables
extern "C" __attribute__((noinline))
int64_t trace_target_function(int32_t op_code, int64_t input_val, uint32_t count) {
    // 2. Local character buffer
    char local_tag[32];
    snprintf(local_tag, sizeof(local_tag), "OP_%d_%u", op_code, count);

    // 1. Stack-allocated struct with scalar and array fields
    SensorReading reading;
    reading.sensor_id = static_cast<uint32_t>(op_code * 100);
    reading.status_code = 1;
    reading.calibration_factor = 2.5;
    reading.sample_counts[0] = 10;
    reading.sample_counts[1] = 20;
    reading.sample_counts[2] = 30;
    reading.sample_counts[3] = 40;

    // Scalar local variables
    int32_t local_accum = 42;
    int64_t local_scaled = input_val * 2;

    // 3. Nested function call
    int32_t inner_res = compute_inner_metric(local_accum, op_code, local_tag);

    // Combined calculation
    int64_t final_metric = local_scaled + inner_res + reading.sample_counts[1];

    // Prevent compiler from optimizing away stack memory in -O2 while keeping variables local
    asm volatile("" : : "r"(&reading), "r"(local_tag), "r"(final_metric) : "memory");

    return final_metric;
}

int main(int argc, char* argv[]) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    int loop_count = 0;
    int interval_ms = 100;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--loop") == 0 && i + 1 < argc) {
            loop_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--interval-ms") == 0 && i + 1 < argc) {
            interval_ms = atoi(argv[++i]);
        }
    }

#ifdef OPTIMIZED_BUILD
    const char* build_mode = "OPTIMIZED_O2";
#else
    const char* build_mode = "DEBUG_O0";
#endif

    // Deterministic startup marker with PID and function addresses
    printf("READY pid=%d target_func=%p inner_func=%p build_mode=%s\n",
           getpid(),
           (void*)&trace_target_function,
           (void*)&compute_inner_metric,
           build_mode);
    fflush(stdout);

    if (loop_count > 0) {
        // Autonomous mode: invoke periodically
        for (int i = 0; i < loop_count && g_running; ++i) {
            int64_t res = trace_target_function(i + 1, (i + 1) * 10, i + 5);
            printf("AUTO_CALL iter=%d res=%lld\n", i, static_cast<long long>(res));
            fflush(stdout);
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
        printf("EXIT_AUTO\n");
        fflush(stdout);
        return 0;
    }

    // Interactive command loop on stdin
    char line[256];
    while (g_running && fgets(line, sizeof(line), stdin)) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        char* cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        if (strcmp(line, "QUIT") == 0 || strcmp(line, "STOP") == 0) {
            printf("BYE\n");
            fflush(stdout);
            break;
        } else if (strncmp(line, "CALL ", 5) == 0) {
            int32_t op = 1;
            int64_t val = 100;
            uint32_t cnt = 5;
            sscanf(line + 5, "%d %lld %u", &op, reinterpret_cast<long long*>(&val), &cnt);
            int64_t ret = trace_target_function(op, val, cnt);
            printf("RESULT ret=%lld\n", static_cast<long long>(ret));
            fflush(stdout);
        } else if (strcmp(line, "PING") == 0) {
            printf("PONG\n");
            fflush(stdout);
        }
    }

    return 0;
}
