#include "../include/collector.h"
#include "../include/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

static int load_key_from_file(const char *path, char *out_key, size_t max_len) {
    if (!path || path[0] == '\0' || !out_key || max_len == 0) return -1;
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        fprintf(stderr, "Error: Failed to open key file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: Key file '%s' is not a regular file.\n", path);
        close(fd);
        return -1;
    }

    /* Reject any group or world access permissions (must be 0600 or 0400) */
    if ((st.st_mode & 0077) != 0) {
        fprintf(stderr, "Error: Key file '%s' has insecure permissions (mode 0%o). Must be 0600 or 0400.\n",
                path, (unsigned int)(st.st_mode & 0777));
        close(fd);
        return -1;
    }

    /* Verify ownership matches current user or root */
    if (st.st_uid != geteuid() && st.st_uid != 0) {
        fprintf(stderr, "Error: Key file '%s' UID (%u) does not match process UID (%u).\n",
                path, (unsigned int)st.st_uid, (unsigned int)geteuid());
        close(fd);
        return -1;
    }

    /* Reject oversized files early */
    if (st.st_size > 512) {
        fprintf(stderr, "Error: Key file '%s' is oversized (%lld bytes; maximum is 512 bytes).\n",
                path, (long long)st.st_size);
        close(fd);
        return -1;
    }

    char buf[512];
    secure_memzero(buf, sizeof(buf));
    size_t total_read = 0;

    while (total_read < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total_read, sizeof(buf) - 1 - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Error: Failed to read key file '%s': %s\n", path, strerror(errno));
            close(fd);
            secure_memzero(buf, sizeof(buf));
            return -1;
        }
        if (n == 0) break;
        total_read += (size_t)n;
    }

    /* Verify EOF and detect oversized input, retrying on EINTR */
    char extra[1];
    ssize_t extra_n;
    while ((extra_n = read(fd, extra, sizeof(extra))) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "Error: Failed to verify EOF for key file '%s': %s\n", path, strerror(errno));
        close(fd);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }
    close(fd);
    if (extra_n > 0) {
        fprintf(stderr, "Error: Key file '%s' is oversized (exceeds buffer limit).\n", path);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    /* Reject embedded NUL bytes */
    for (size_t i = 0; i < total_read; ++i) {
        if (buf[i] == '\0') {
            fprintf(stderr, "Error: Key in '%s' contains forbidden embedded NUL byte.\n", path);
            secure_memzero(buf, sizeof(buf));
            return -1;
        }
    }

    /* Trim trailing newline and carriage return */
    size_t len = total_read;
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[len - 1] = '\0';
        len--;
    }

    if (len < 16) {
        fprintf(stderr, "Error: Key in '%s' is too short (%zu bytes; minimum is 16 bytes).\n", path, len);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    if (len >= max_len) {
        fprintf(stderr, "Error: Key in '%s' is oversized (%zu bytes; maximum is %zu bytes).\n", path, len, max_len - 1);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    if (strchr(buf, '|') != NULL) {
        fprintf(stderr, "Error: Key in '%s' contains forbidden delimiter '|'.\n", path);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    memcpy(out_key, buf, len);
    out_key[len] = '\0';
    secure_memzero(buf, sizeof(buf));
    return 0;
}

/*
 * load_key_from_fd:
 * Ingests a signing key from an inherited file descriptor.
 *
 * FD OWNERSHIP CONTRACT:
 * The Collector takes immediate ownership of the passed descriptor (fd).
 * In all return paths (error or success), the descriptor is guaranteed to be closed
 * by this function, ensuring no resource leak or descriptor retention in the process.
 */
static int load_key_from_fd(int fd, char *out_key, size_t max_len) {
    if (fd < 0 || !out_key || max_len == 0) {
        if (fd >= 0) close(fd);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error: Failed to stat key FD %d: %s\n", fd, strerror(errno));
        close(fd);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISFIFO(st.st_mode) && !S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "Error: Key FD %d is not a regular file, pipe, or socket.\n", fd);
        close(fd);
        return -1;
    }

    char buf[512];
    secure_memzero(buf, sizeof(buf));
    size_t total_read = 0;

    while (total_read < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total_read, sizeof(buf) - 1 - total_read);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Error: Failed to read key from FD %d: %s\n", fd, strerror(errno));
            close(fd);
            secure_memzero(buf, sizeof(buf));
            return -1;
        }
        if (n == 0) break;
        total_read += (size_t)n;
    }

    /* Verify EOF and detect oversized input, retrying on EINTR */
    char extra[1];
    ssize_t extra_n;
    while ((extra_n = read(fd, extra, sizeof(extra))) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "Error: Failed to verify EOF for key FD %d: %s\n", fd, strerror(errno));
        close(fd);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }
    close(fd);
    if (extra_n > 0) {
        fprintf(stderr, "Error: Key from FD %d is oversized (exceeds buffer limit).\n", fd);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    /* Reject embedded NUL bytes */
    for (size_t i = 0; i < total_read; ++i) {
        if (buf[i] == '\0') {
            fprintf(stderr, "Error: Key from FD %d contains forbidden embedded NUL byte.\n", fd);
            secure_memzero(buf, sizeof(buf));
            return -1;
        }
    }

    size_t len = total_read;
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[len - 1] = '\0';
        len--;
    }

    if (len < 16) {
        fprintf(stderr, "Error: Key from FD %d is too short (%zu bytes; minimum is 16 bytes).\n", fd, len);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    if (len >= max_len) {
        fprintf(stderr, "Error: Key from FD %d is oversized (%zu bytes; maximum is %zu bytes).\n", fd, len, max_len - 1);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    if (strchr(buf, '|') != NULL) {
        fprintf(stderr, "Error: Key from FD %d contains forbidden delimiter '|'.\n", fd);
        secure_memzero(buf, sizeof(buf));
        return -1;
    }

    memcpy(out_key, buf, len);
    out_key[len] = '\0';
    secure_memzero(buf, sizeof(buf));
    return 0;
}

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
        "  -F, --key-file <PATH>   Path to secure file containing signing key (0600/0400 mode)\n"
        "  -D, --key-fd <FD>       Inherited file descriptor containing signing key\n"
        "  -I, --key-id <ID>       Key ID for attestation (default: default)\n"
        "  -S, --session-id <ID>   Investigation session ID\n"
        "      --test-crypto       Run cryptographic self-test against FIPS/RFC vectors\n"
        "      --version           Print collector version and exit\n"
        "  -h, --help              Show this help message\n\n"
        "Example:\n"
        "  %s -o /tmp/snapshot_1234 1234\n",
        prog, prog);
}

#ifndef COLLECTOR_VERSION
#define COLLECTOR_VERSION "dev"
#endif
/* Greppable marker so the host can read the version from a binary it cannot execute. */
static const char collector_version_marker[] = "DS_COLLECTOR_VERSION=" COLLECTOR_VERSION;

int main(int argc, char *argv[]) {
    if (argc == 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("dynamicstate-collector %s\n", collector_version_marker + sizeof("DS_COLLECTOR_VERSION=") - 1);
        return 0;
    }
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
        {"key-file", required_argument, 0, 'F'},
        {"key-fd", required_argument, 0, 'D'},
        {"key-id", required_argument, 0, 'I'},
        {"session-id", required_argument, 0, 'S'},
        {"test-crypto", no_argument, 0, 1001},
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

    while ((opt = getopt_long(argc, argv, "p:o:m:r:P:B:s:dt:jvF:D:I:S:h", long_options, &option_index)) != -1) {
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
            case 'F':
                strncpy(cfg.key_file, optarg, sizeof(cfg.key_file) - 1);
                break;
            case 'D': {
                char *endptr = NULL;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);
                if (errno != 0 || endptr == optarg || *endptr != '\0' || val < 0 || val > 1048576L) {
                    fprintf(stderr, "Error: Invalid --key-fd '%s' (must be integer between 0 and 1048576).\n", optarg);
                    if (cfg.json_output) {
                        fprintf(stdout, "{\"success\":false,\"error\":\"INVALID_KEY_FD\",\"pid\":0,\"status\":\"FAILED\"}\n");
                        fflush(stdout);
                    }
                    return 1;
                }
                cfg.key_fd = (int)val;
                break;
            }
            case 'I':
                strncpy(cfg.signing_key_id, optarg, sizeof(cfg.signing_key_id) - 1);
                break;
            case 'S':
                strncpy(cfg.session_id, optarg, sizeof(cfg.session_id) - 1);
                break;
            case 1001: {
                int selftest_res = collector_crypto_selftest();
                if (selftest_res == 0) {
                    printf("PASS: All FIPS 180-4 and RFC 4231 vectors validated in C.\n");
                    return 0;
                } else {
                    fprintf(stderr, "FAIL: Cryptographic self-test failed in C.\n");
                    return 1;
                }
            }
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

    /* Load key from file or FD if specified */
    if (cfg.key_file[0] != '\0') {
        if (load_key_from_file(cfg.key_file, cfg.signing_key, sizeof(cfg.signing_key)) != 0) {
            fprintf(stderr, "Error: Failed to load signing key from file '%s'.\n", cfg.key_file);
            secure_memzero(cfg.signing_key, sizeof(cfg.signing_key));
            return 1;
        }
    } else if (cfg.key_fd >= 0) {
        if (load_key_from_fd(cfg.key_fd, cfg.signing_key, sizeof(cfg.signing_key)) != 0) {
            fprintf(stderr, "Error: Failed to load signing key from FD %d.\n", cfg.key_fd);
            secure_memzero(cfg.signing_key, sizeof(cfg.signing_key));
            return 1;
        }
    }

    /* Key ID and Session ID non-secret metadata fallbacks */
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
    /* Memory scrub sensitive signing key immediately after capture */
    secure_memzero(cfg.signing_key, sizeof(cfg.signing_key));
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
