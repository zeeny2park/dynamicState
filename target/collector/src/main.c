#include "../include/collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "dynamicState Native Target-Side Memory Collector\n"
        "Captures memory snapshots on embedded/remote Linux targets with ZERO Python/GDB dependencies.\n\n"
        "Usage: %s [OPTIONS] <PID>\n\n"
        "Options:\n"
        "  -p, --pid <PID>         Target process PID to capture\n"
        "  -o, --output <DIR>      Output directory (default: raw_snapshot_<PID>)\n"
        "  -m, --max-mb <MB>       Maximum total bytes in MB to capture (default: 64)\n"
        "      --max-region <MB>   Maximum per-region bytes in MB (default: 32)\n"
        "      --policy <POLICY>   all (default), heap_stack, writable\n"
        "      --backend <NAME>    auto (default), pread, process_vm_readv\n"
        "  -t, --timeout-ms <MS>   Maximum capture wall-clock timeout in ms (default: unlimited)\n"
        "  -j, --json              Output machine-readable JSON metadata to stdout\n"
        "  -v, --verbose           Enable verbose progress logging\n"
        "  -h, --help              Show this help message\n\n"
        "Example:\n"
        "  %s -o /tmp/snapshot_1234 1234\n",
        prog, prog);
}

int main(int argc, char *argv[]) {
    collector_config_t cfg;
    collector_init_config(&cfg);

    static struct option long_options[] = {
        {"pid", required_argument, 0, 'p'},
        {"output", required_argument, 0, 'o'},
        {"max-mb", required_argument, 0, 'm'},
        {"max-region", required_argument, 0, 'r'},
        {"policy", required_argument, 0, 'P'},
        {"backend", required_argument, 0, 'B'},
        {"read-slices", required_argument, 0, 's'},
        {"daemon", no_argument, 0, 'd'},
        {"timeout-ms", required_argument, 0, 't'},
        {"json", no_argument, 0, 'j'},
        {"verbose", no_argument, 0, 'v'},
        {"signing-key", required_argument, 0, 'K'},
        {"key-id", required_argument, 0, 'I'},
        {"session-id", required_argument, 0, 'S'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    const char *pid_str = NULL;
    const char *timeout_str = NULL;
    const char *max_mb_str = NULL;
    const char *max_region_str = NULL;
    const char *read_slices_spec = NULL;
    int daemon_mode = 0;
    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "p:o:m:r:P:B:s:dt:jvK:I:S:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                pid_str = optarg;
                break;
            case 'o':
                strncpy(cfg.output_dir, optarg, sizeof(cfg.output_dir) - 1);
                break;
            case 'm':
                max_mb_str = optarg;
                break;
            case 'r':
                max_region_str = optarg;
                break;
            case 'K':
                strncpy(cfg.signing_key, optarg, sizeof(cfg.signing_key) - 1);
                break;
            case 'I':
                strncpy(cfg.signing_key_id, optarg, sizeof(cfg.signing_key_id) - 1);
                break;
            case 'S':
                strncpy(cfg.session_id, optarg, sizeof(cfg.session_id) - 1);
                break;
            case 'P':
                if (strcmp(optarg, "heap_stack") == 0) {
                    cfg.policy = POLICY_HEAP_STACK;
                } else if (strcmp(optarg, "writable") == 0) {
                    cfg.policy = POLICY_WRITABLE;
                } else {
                    cfg.policy = POLICY_ALL_READABLE;
                }
                break;
            case 'B':
                if (strcmp(optarg, "pread") == 0) {
                    cfg.backend = BACKEND_PROC_MEM;
                } else if (strcmp(optarg, "process_vm_readv") == 0) {
                    cfg.backend = BACKEND_VM_READV;
                } else {
                    cfg.backend = BACKEND_AUTO;
                }
                break;
            case 's':
                read_slices_spec = optarg;
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 't':
                timeout_str = optarg;
                break;
            case 'j':
                cfg.json_output = 1;
                break;
            case 'v':
                cfg.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (daemon_mode) {
        return collector_daemon_loop(cfg.backend, stdin, stdout);
    }

    /* Fallback to environment variables for cryptographic attestation */
    if (cfg.signing_key[0] == '\0') {
        const char *env_k = getenv("DYNAMICSTATE_COLLECTOR_KEY");
        if (!env_k) env_k = getenv("DYNAMICSTATE_CAPTURE_SECRET");
        if (env_k && env_k[0] != '\0') {
            strncpy(cfg.signing_key, env_k, sizeof(cfg.signing_key) - 1);
        }
    }
    if (cfg.signing_key_id[0] == '\0') {
        const char *env_kid = getenv("DYNAMICSTATE_COLLECTOR_KEY_ID");
        if (!env_kid) env_kid = getenv("DYNAMICSTATE_CAPTURE_KEY_ID");
        if (env_kid && env_kid[0] != '\0') {
            strncpy(cfg.signing_key_id, env_kid, sizeof(cfg.signing_key_id) - 1);
        }
    }
    if (cfg.session_id[0] == '\0') {
        const char *env_sid = getenv("DYNAMICSTATE_COLLECTOR_SESSION_ID");
        if (env_sid && env_sid[0] != '\0') {
            strncpy(cfg.session_id, env_sid, sizeof(cfg.session_id) - 1);
        }
    }

    /* Positional PID argument if not supplied via -p */
    if (!pid_str && optind < argc) {
        pid_str = argv[optind];
    }

    /* Validate timeout argument */
    if (timeout_str != NULL) {
        char *endptr = NULL;
        errno = 0;
        long long t_val = strtoll(timeout_str, &endptr, 10);
        if (errno != 0 || endptr == timeout_str || *endptr != '\0' || t_val < 0 || t_val > 3600000LL) {
            fprintf(stderr, "Error: Invalid timeout-ms '%s' (must be integer between 0 and 3600000 ms).\n", timeout_str);
            if (cfg.json_output) {
                fprintf(stdout, "{\"success\":false,\"error\":\"INVALID_TIMEOUT\",\"pid\":0,\"status\":\"FAILED\"}\n");
                fflush(stdout);
            }
            return 1;
        }
        cfg.timeout_ms = (uint32_t)t_val;
    }

    /* Validate max_mb argument */
    if (max_mb_str != NULL) {
        char *endptr = NULL;
        errno = 0;
        long long mb_val = strtoll(max_mb_str, &endptr, 10);
        if (errno != 0 || endptr == max_mb_str || *endptr != '\0' || mb_val <= 0 || mb_val > 16384LL) {
            fprintf(stderr, "Error: Invalid max-mb '%s'.\n", max_mb_str);
            if (cfg.json_output) {
                fprintf(stdout, "{\"success\":false,\"error\":\"INVALID_ARGUMENTS\",\"pid\":0,\"status\":\"FAILED\"}\n");
                fflush(stdout);
            }
            return 1;
        }
        cfg.max_total_bytes = (size_t)mb_val * 1024 * 1024;
    }

    /* Validate max_region argument */
    if (max_region_str != NULL) {
        char *endptr = NULL;
        errno = 0;
        long long reg_val = strtoll(max_region_str, &endptr, 10);
        if (errno != 0 || endptr == max_region_str || *endptr != '\0' || reg_val <= 0 || reg_val > 4096LL) {
            fprintf(stderr, "Error: Invalid max-region '%s'.\n", max_region_str);
            if (cfg.json_output) {
                fprintf(stdout, "{\"success\":false,\"error\":\"INVALID_ARGUMENTS\",\"pid\":0,\"status\":\"FAILED\"}\n");
                fflush(stdout);
            }
            return 1;
        }
        cfg.max_region_bytes = (size_t)reg_val * 1024 * 1024;
    }

    /* Validate PID */
    if (pid_str != NULL) {
        char *endptr = NULL;
        errno = 0;
        long long p_val = strtoll(pid_str, &endptr, 10);
        if (errno != 0 || endptr == pid_str || *endptr != '\0' || p_val <= 0 || p_val > 4194304LL) {
            fprintf(stderr, "Error: Invalid PID '%s' (must be integer > 0).\n", pid_str);
            if (cfg.json_output) {
                fprintf(stdout, "{\"success\":false,\"error\":\"INVALID_PID\",\"pid\":0,\"status\":\"FAILED\"}\n");
                fflush(stdout);
            }
            return 1;
        }
        cfg.pid = (pid_t)p_val;
    } else {
        fprintf(stderr, "Error: Valid PID required.\n");
        print_usage(argv[0]);
        if (cfg.json_output) {
            fprintf(stdout, "{\"success\":false,\"error\":\"MISSING_PID\",\"pid\":0,\"status\":\"FAILED\"}\n");
            fflush(stdout);
        }
        return 1;
    }

    if (read_slices_spec != NULL) {
        return (collector_read_slices(cfg.pid, cfg.backend, read_slices_spec, stdout) == 0) ? 0 : 1;
    }

    if (cfg.output_dir[0] == '\0') {
        snprintf(cfg.output_dir, sizeof(cfg.output_dir), "raw_snapshot_%d", (int)cfg.pid);
    }
    snprintf(cfg.snapshot_id, sizeof(cfg.snapshot_id), "SNAP_%d", (int)cfg.pid);

    if (!cfg.json_output) {
        printf("[dynamicState-collector] Capturing target PID %d to directory '%s'...\n", (int)cfg.pid, cfg.output_dir);
    } else if (cfg.verbose) {
        fprintf(stderr, "[dynamicState-collector] Capturing target PID %d to directory '%s'...\n", (int)cfg.pid, cfg.output_dir);
    }

    collector_stats_t stats;
    int res = collector_run(&cfg, &stats);
    if (res != 0) {
        fprintf(stderr, "[dynamicState-collector] Error: Failed to capture memory for PID %d (status: %s).\n",
                (int)cfg.pid, stats.status[0] ? stats.status : "FAILED");
        if (cfg.json_output) {
            fprintf(stdout, "{\"success\":false,\"error\":\"%s\",\"pid\":%d,\"status\":\"%s\"}\n",
                    stats.status[0] ? stats.status : "FAILED", (int)cfg.pid, stats.status[0] ? stats.status : "FAILED");
            fflush(stdout);
        }
        return 1;
    }

    if (cfg.json_output) {
        char meta_path[2048];
        snprintf(meta_path, sizeof(meta_path), "%s/metadata.json", cfg.output_dir);
        FILE *mf = fopen(meta_path, "r");
        if (mf) {
            char fbuf[4096];
            size_t n;
            while ((n = fread(fbuf, 1, sizeof(fbuf), mf)) > 0) {
                if (fwrite(fbuf, 1, n, stdout) != n) break;
            }
            fclose(mf);
        } else {
            fprintf(stdout, "{\"success\":false,\"error\":\"METADATA_READ_FAILED\",\"pid\":%d,\"status\":\"%s\"}\n",
                    (int)cfg.pid, stats.status);
            fflush(stdout);
            return 1;
        }
        fflush(stdout);
        if (strcmp(stats.status, "FAILED") == 0 ||
            strcmp(stats.status, "PROCESS_EXITED") == 0 ||
            strcmp(stats.status, "PERMISSION_DENIED") == 0 ||
            strcmp(stats.status, "TIMEOUT") == 0) {
            return 1;
        }
        return 0;
    }

    printf("[dynamicState-collector] Capture finished: %s\n", stats.status);
    printf("  Regions captured: %d / %d requested (found in maps: %d)\n",
           stats.regions_captured, stats.regions_requested, stats.regions_found);
    printf("  Bytes captured:   %zu bytes (%.2f MB)\n", stats.bytes_captured, (double)stats.bytes_captured / (1024.0 * 1024.0));
    printf("  Duration:         %.2f ms (backend: %s)\n", stats.duration_us / 1000.0, stats.backend_used);
    printf("  Architecture:     %s (%s)\n", stats.arch, stats.elf_class);
    printf("  Artifacts stored in: %s\n", cfg.output_dir);

    if (strcmp(stats.status, "FAILED") == 0 ||
        strcmp(stats.status, "PROCESS_EXITED") == 0 ||
        strcmp(stats.status, "PERMISSION_DENIED") == 0 ||
        strcmp(stats.status, "TIMEOUT") == 0) {
        return 1;
    }
    return 0;
}
