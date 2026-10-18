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

// Overloaded C++ functions for testing ambiguous function resolution
__attribute__((noinline))
int32_t overloaded_metric(int32_t a) {
    return a * 2;
}

__attribute__((noinline))
int32_t overloaded_metric(int32_t a, int32_t b) {
    return a + b;
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

// 5. Canonical scalar type coverage (i8, i16, i32, i64, u8, u16, u32, u64, float, double, bool, pointer)
extern "C" __attribute__((noinline))
double test_all_scalars(
    int8_t i8,
    int16_t i16,
    int32_t i32,
    int64_t i64,
    uint8_t u8,
    uint16_t u16,
    uint32_t u32,
    uint64_t u64,
    float f32,
    double f64,
    bool flag,
    const char* ptr
) {
    int8_t local_i8 = static_cast<int8_t>(i8 + 1);
    int16_t local_i16 = static_cast<int16_t>(i16 + 2);
    int32_t local_i32 = i32 + 3;
    int64_t local_i64 = i64 + 4;
    uint8_t local_u8 = static_cast<uint8_t>(u8 + 5);
    uint16_t local_u16 = static_cast<uint16_t>(u16 + 6);
    uint32_t local_u32 = u32 + 7;
    uint64_t local_u64 = u64 + 8;
    float local_f32 = f32 * 2.0f;
    double local_f64 = f64 * 3.0;
    bool local_flag = !flag;
    const char* local_ptr = ptr;

    asm volatile("" : : "r"(&local_i8), "r"(&local_i16), "r"(&local_i32), "r"(&local_i64),
                        "r"(&local_u8), "r"(&local_u16), "r"(&local_u32), "r"(&local_u64),
                        "r"(&local_f32), "r"(&local_f64), "r"(&local_flag), "r"(&local_ptr) : "memory");

    return static_cast<double>(local_i32) + static_cast<double>(local_f32) + local_f64;
}

// 6. Parameter register clobbering test
extern "C" __attribute__((noinline))
int64_t test_clobbered_param(int64_t val, int32_t mult) {
    int64_t acc = val * mult;
    int32_t inner = compute_inner_metric(static_cast<int32_t>(val), mult, "clobber");
    acc += inner;
    return acc + val;
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
    printf("READY pid=%d target_func=%p inner_func=%p scalars_func=%p clobber_func=%p build_mode=%s\n",
           getpid(),
           (void*)&trace_target_function,
           (void*)&compute_inner_metric,
           (void*)&test_all_scalars,
           (void*)&test_clobbered_param,
           build_mode);
    fflush(stdout);

    if (loop_count > 0) {
        // Autonomous mode: invoke periodically
        for (int i = 0; i < loop_count && g_running; ++i) {
            int64_t res = trace_target_function(i + 1, (i + 1) * 10, i + 5);
            int32_t ov1 = overloaded_metric(i + 1);
            int32_t ov2 = overloaded_metric(i + 1, i + 2);
            double sc_ret = test_all_scalars(-8, -16, -32, -64, 8, 16, 32, 64, 1.25f, 2.75, true, "autotag");
            int64_t cl_ret = test_clobbered_param(100 + i, 3);
            printf("AUTO_CALL iter=%d res=%lld ov1=%d ov2=%d sc=%.2f cl=%lld\n",
                   i, static_cast<long long>(res), ov1, ov2, sc_ret, static_cast<long long>(cl_ret));
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
        } else if (strncmp(line, "CALL_OV1 ", 9) == 0) {
            int32_t a = 1;
            sscanf(line + 9, "%d", &a);
            int32_t ret = overloaded_metric(a);
            printf("RESULT_OV1 ret=%d\n", ret);
            fflush(stdout);
        } else if (strncmp(line, "CALL_OV2 ", 9) == 0) {
            int32_t a = 1, b = 2;
            sscanf(line + 9, "%d %d", &a, &b);
            int32_t ret = overloaded_metric(a, b);
            printf("RESULT_OV2 ret=%d\n", ret);
            fflush(stdout);
        } else if (strncmp(line, "CALL_SCALARS", 12) == 0) {
            double ret = test_all_scalars(-8, -16, -32, -64, 8, 16, 32, 64, 1.25f, 2.75, true, "hellotag");
            printf("RESULT_SCALARS ret=%.2f\n", ret);
            fflush(stdout);
        } else if (strncmp(line, "CALL_CLOBBER", 12) == 0) {
            int64_t ret = test_clobbered_param(100, 3);
            printf("RESULT_CLOBBER ret=%lld\n", static_cast<long long>(ret));
            fflush(stdout);
        } else if (strcmp(line, "PING") == 0) {
            printf("PONG\n");
            fflush(stdout);
        }
    }

    return 0;
}
