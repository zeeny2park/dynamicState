#include "../include/collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

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
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:o:m:r:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                cfg.pid = (pid_t)atoi(optarg);
                break;
            case 'o':
                strncpy(cfg.output_dir, optarg, sizeof(cfg.output_dir) - 1);
                break;
            case 'm':
                cfg.max_total_bytes = (size_t)atoi(optarg) * 1024 * 1024;
                break;
            case 'r':
                cfg.max_region_bytes = (size_t)atoi(optarg) * 1024 * 1024;
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

    /* Positional PID argument if not supplied via -p */
    if (cfg.pid <= 0 && optind < argc) {
        cfg.pid = (pid_t)atoi(argv[optind]);
    }

    if (cfg.pid <= 0) {
        fprintf(stderr, "Error: Valid PID required.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (cfg.output_dir[0] == '\0') {
        snprintf(cfg.output_dir, sizeof(cfg.output_dir), "raw_snapshot_%d", (int)cfg.pid);
    }
    snprintf(cfg.snapshot_id, sizeof(cfg.snapshot_id), "SNAP_%d", (int)cfg.pid);

    printf("[dynamicState-collector] Capturing target PID %d to directory '%s'...\n", (int)cfg.pid, cfg.output_dir);

    collector_stats_t stats;
    int res = collector_run(&cfg, &stats);
    if (res != 0) {
        fprintf(stderr, "[dynamicState-collector] Error: Failed to capture memory for PID %d.\n", (int)cfg.pid);
        return 1;
    }

    printf("[dynamicState-collector] Capture finished: %s\n", stats.status);
    printf("  Regions captured: %d / %d requested (found in maps: %d)\n",
           stats.regions_captured, stats.regions_requested, stats.regions_found);
    printf("  Bytes captured:   %zu bytes (%.2f MB)\n", stats.bytes_captured, (double)stats.bytes_captured / (1024.0 * 1024.0));
    printf("  Duration:         %.2f ms (backend: %s)\n", stats.duration_us / 1000.0, stats.backend_used);
    printf("  Architecture:     %s (%s)\n", stats.arch, stats.elf_class);
    printf("  Artifacts stored in: %s\n", cfg.output_dir);

    return 0;
}
