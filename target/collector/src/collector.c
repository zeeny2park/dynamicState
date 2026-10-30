#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "../include/collector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/uio.h>

#define MAX_LINE 2048

static int64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static void escape_json_string(const char *in, char *out, size_t max_out) {
    size_t i = 0, j = 0;
    while (in && in[i] && j + 2 < max_out) {
        if (in[i] == '\\' || in[i] == '"') {
            out[j++] = '\\';
            out[j++] = in[i++];
        } else if (in[i] == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
            i++;
        } else if (in[i] == '\t') {
            out[j++] = '\\';
            out[j++] = 't';
            i++;
        } else {
            out[j++] = in[i++];
        }
    }
    out[j] = '\0';
}

void collector_init_config(collector_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->pid = 0;
    cfg->max_total_bytes = 64 * 1024 * 1024;   /* 64 MB */
    cfg->max_region_bytes = 32 * 1024 * 1024;  /* 32 MB */
    cfg->policy = POLICY_ALL_READABLE;
    cfg->backend = BACKEND_AUTO;
    cfg->verbose = 0;
    cfg->timeout_ms = 0;                       /* 0 = unlimited */
    cfg->json_output = 0;
}

int collector_get_exe_path(pid_t pid, char *buf, size_t buf_size) {
    char link_path[128];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", (int)pid);
    ssize_t len = readlink(link_path, buf, buf_size - 1);
    if (len > 0) {
        buf[len] = '\0';
        return 0;
    }
    buf[0] = '\0';
    return -1;
}

int collector_get_process_starttime(pid_t pid, uint64_t *starttime_out) {
    if (pid <= 0 || !starttime_out) return -1;
    char stat_path[128];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", (int)pid);
    FILE *fp = fopen(stat_path, "r");
    if (!fp) {
        return -1;
    }
    char line[4096];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char *paren = strrchr(line, ')');
    if (!paren) return -1;

    char *p = paren + 1;
    while (*p == ' ' || *p == '\t') p++;

    for (int field = 3; field < 22; field++) {
        char *space = strchr(p, ' ');
        if (!space) return -1;
        p = space + 1;
        while (*p == ' ' || *p == '\t') p++;
    }

    char *endptr = NULL;
    uint64_t st = strtoull(p, &endptr, 10);
    if (endptr == p) return -1;

    *starttime_out = st;
    return 0;
}

int collector_compare_maps(const parsed_region_t *before, int count_before, const parsed_region_t *after, int count_after) {
    if (!before || !after) return -1;
    if (count_before != count_after) {
        return 1;
    }
    for (int i = 0; i < count_before; i++) {
        if (before[i].start != after[i].start ||
            before[i].end != after[i].end ||
            before[i].offset != after[i].offset ||
            before[i].inode != after[i].inode ||
            strcmp(before[i].perms, after[i].perms) != 0 ||
            strcmp(before[i].device, after[i].device) != 0 ||
            strcmp(before[i].pathname, after[i].pathname) != 0) {
            return 1;
        }
    }
    return 0;
}

void collector_classify_region(parsed_region_t *r, const char *exe_path) {
    if (!r) return;
    if (strstr(r->pathname, "[heap]")) {
        snprintf(r->category, sizeof(r->category), "heap");
    } else if (strstr(r->pathname, "[stack]")) {
        snprintf(r->category, sizeof(r->category), "stack");
    } else if (strstr(r->pathname, ".so")) {
        snprintf(r->category, sizeof(r->category), "shared_library");
    } else if (exe_path && exe_path[0] && strcmp(r->pathname, exe_path) == 0) {
        if (r->executable) {
            snprintf(r->category, sizeof(r->category), "executable");
        } else if (r->writable) {
            snprintf(r->category, sizeof(r->category), "global");
        } else {
            snprintf(r->category, sizeof(r->category), "executable");
        }
    } else if (strstr(r->pathname, "[anon") || strlen(r->pathname) == 0) {
        if (r->writable) {
            snprintf(r->category, sizeof(r->category), "heap");
        } else {
            snprintf(r->category, sizeof(r->category), "other");
        }
    } else {
        snprintf(r->category, sizeof(r->category), "other");
    }
}

int collector_parse_maps(pid_t pid, const char *exe_path, parsed_region_t **regions_out, int *count_out) {
    char maps_path[128];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) {
        return -1;
    }

    int capacity = 64;
    int count = 0;
    parsed_region_t *list = (parsed_region_t *)malloc(capacity * sizeof(parsed_region_t));
    if (!list) {
        fclose(fp);
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp)) {
        if (count >= capacity) {
            capacity *= 2;
            parsed_region_t *new_list = (parsed_region_t *)realloc(list, capacity * sizeof(parsed_region_t));
            if (!new_list) {
                free(list);
                fclose(fp);
                return -1;
            }
            list = new_list;
        }

        parsed_region_t *r = &list[count];
        memset(r, 0, sizeof(*r));

        unsigned long start = 0, end = 0, offset = 0, inode = 0;
        char perms[16] = {0};
        char dev[32] = {0};
        char path[512] = {0};

        int matched = sscanf(line, "%lx-%lx %15s %lx %31s %lu %511[^\n]",
                             &start, &end, perms, &offset, dev, &inode, path);
        if (matched < 6) {
            continue;
        }

        r->start = (uint64_t)start;
        r->end = (uint64_t)end;
        r->size = (r->end > r->start) ? (r->end - r->start) : 0;
        snprintf(r->perms, sizeof(r->perms), "%s", perms);
        r->offset = (uint64_t)offset;
        snprintf(r->device, sizeof(r->device), "%s", dev);
        r->inode = (uint64_t)inode;
        if (matched >= 7) {
            char *p = path;
            while (*p == ' ' || *p == '\t') p++;
            snprintf(r->pathname, sizeof(r->pathname), "%s", p);
        }

        r->readable = (strchr(perms, 'r') != NULL);
        r->writable = (strchr(perms, 'w') != NULL);
        r->executable = (strchr(perms, 'x') != NULL);

        collector_classify_region(r, exe_path);
        count++;
    }

    fclose(fp);
    *regions_out = list;
    *count_out = count;
    return 0;
}

int collector_filter_regions(parsed_region_t *regions, int count, const collector_config_t *cfg, int *selected_count_out) {
    if (!regions || count <= 0 || !cfg) return 0;

    size_t cumulative_bytes = 0;
    int selected = 0;

    for (int i = 0; i < count; i++) {
        parsed_region_t *r = &regions[i];
        r->is_selected = 0;

        if (!r->readable) continue;

        /* Skip special kernel virtual mappings */
        if (strcmp(r->pathname, "[vvar]") == 0 ||
            strcmp(r->pathname, "[vdso]") == 0 ||
            strcmp(r->pathname, "[vsyscall]") == 0 ||
            strcmp(r->pathname, "[usertrap]") == 0) {
            continue;
        }

        if (cfg->policy == POLICY_HEAP_STACK) {
            if (strcmp(r->category, "heap") != 0 && strcmp(r->category, "stack") != 0) {
                continue;
            }
        } else if (cfg->policy == POLICY_WRITABLE) {
            if (!r->writable) {
                continue;
            }
        }

        /* Check size bounds */
        size_t region_size = (size_t)r->size;
        if (cfg->max_region_bytes > 0 && region_size > cfg->max_region_bytes) {
            region_size = cfg->max_region_bytes;
        }

        if (cfg->max_total_bytes > 0 && cumulative_bytes + region_size > cfg->max_total_bytes) {
            break;
        }

        r->is_selected = 1;
        cumulative_bytes += region_size;
        selected++;
    }

    if (selected_count_out) {
        *selected_count_out = selected;
    }
    return selected;
}

int collector_read_region(pid_t pid, int mem_fd, int backend, uint64_t start, size_t size, void *buf, size_t *bytes_read) {
    if (!buf || size == 0) return -1;
    *bytes_read = 0;

    if (backend == BACKEND_VM_READV || backend == BACKEND_AUTO) {
        struct iovec local_iov;
        local_iov.iov_base = buf;
        local_iov.iov_len = size;

        struct iovec remote_iov;
        remote_iov.iov_base = (void *)(uintptr_t)start;
        remote_iov.iov_len = size;

        ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
        if (nread >= 0) {
            *bytes_read = (size_t)nread;
            return 0;
        }
        int vm_err = errno;
        if (vm_err == EINTR) {
            nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
            if (nread >= 0) {
                *bytes_read = (size_t)nread;
                return 0;
            }
            vm_err = errno;
        }
        if (backend == BACKEND_VM_READV) {
            return -1;
        }
    }

    if (mem_fd >= 0) {
        ssize_t nread = pread(mem_fd, buf, size, (off_t)start);
        if (nread >= 0) {
            *bytes_read = (size_t)nread;
            return 0;
        }
        int pread_err = errno;
        if (pread_err == EINTR) {
            nread = pread(mem_fd, buf, size, (off_t)start);
            if (nread >= 0) {
                *bytes_read = (size_t)nread;
                return 0;
            }
        }
    }

    return -1;
}

static int copy_maps_file(pid_t pid, const char *dest_dir) {
    char src[128], dst[2048], tmp[2048];
    if (snprintf(src, sizeof(src), "/proc/%d/maps", (int)pid) >= (int)sizeof(src)) return -1;
    if (snprintf(dst, sizeof(dst), "%s/maps.txt", dest_dir) >= (int)sizeof(dst)) return -1;
    if (snprintf(tmp, sizeof(tmp), "%s/maps.txt.tmp.%d", dest_dir, (int)getpid()) >= (int)sizeof(tmp)) return -1;

    FILE *in = fopen(src, "r");
    if (!in) return -1;
    FILE *out = fopen(tmp, "w");
    if (!out) {
        fclose(in);
        return -1;
    }

    char buf[4096];
    size_t n;
    int write_err = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            write_err = 1;
            break;
        }
    }
    if (ferror(in)) write_err = 1;
    fclose(in);
    if (ferror(out)) write_err = 1;
    if (fclose(out) != 0) write_err = 1;

    if (write_err != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dst) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

int collector_run(const collector_config_t *cfg, collector_stats_t *stats_out) {
    if (!cfg || cfg->pid <= 0) return -1;

    collector_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.page_size = sysconf(_SC_PAGESIZE);

    uint64_t starttime_before = 0;
    if (collector_get_process_starttime(cfg->pid, &starttime_before) < 0) {
        stats.process_exited = 1;
        snprintf(stats.status, sizeof(stats.status), "PROCESS_EXITED");
        if (stats_out) *stats_out = stats;
        return -1;
    }
    stats.process_starttime = starttime_before;

    /* Architecture detection */
    struct utsname uts;
    if (uname(&uts) == 0) {
        snprintf(stats.arch, sizeof(stats.arch), "%s", uts.machine);
    } else {
        snprintf(stats.arch, sizeof(stats.arch), "unknown");
    }

    /* ELF class and endianness */
    if (sizeof(void *) == 8) {
        snprintf(stats.elf_class, sizeof(stats.elf_class), "ELF64");
    } else {
        snprintf(stats.elf_class, sizeof(stats.elf_class), "ELF32");
    }
    /* Uncertainty-first: leave endianness UNKNOWN until analyzed offline */
    snprintf(stats.endianness, sizeof(stats.endianness), "UNKNOWN");

    char exe_path[1024] = {0};
    collector_get_exe_path(cfg->pid, exe_path, sizeof(exe_path));

    parsed_region_t *regions = NULL;
    int region_count = 0;
    if (collector_parse_maps(cfg->pid, exe_path, &regions, &region_count) < 0) {
        if (errno == EACCES || errno == EPERM) {
            snprintf(stats.status, sizeof(stats.status), "PERMISSION_DENIED");
        } else if (errno == ENOENT) {
            stats.process_exited = 1;
            snprintf(stats.status, sizeof(stats.status), "PROCESS_EXITED");
        } else {
            snprintf(stats.status, sizeof(stats.status), "FAILED");
        }
        if (stats_out) *stats_out = stats;
        return -1;
    }
    stats.regions_found = region_count;

    int selected_count = 0;
    collector_filter_regions(regions, region_count, cfg, &selected_count);
    stats.regions_requested = selected_count;

    /* Setup output directory */
    char out_dir[1024];
    if (cfg->output_dir[0]) {
        snprintf(out_dir, sizeof(out_dir), "%s", cfg->output_dir);
    } else {
        snprintf(out_dir, sizeof(out_dir), "raw_snapshot_%d", (int)cfg->pid);
    }
    if (mkdir(out_dir, 0755) != 0 && errno != EEXIST) {
        if (cfg->verbose) {
            fprintf(stderr, "[debug] Failed to create output directory '%s': %s\n", out_dir, strerror(errno));
        }
        snprintf(stats.status, sizeof(stats.status), "FAILED");
        if (stats_out) *stats_out = stats;
        free(regions);
        return -1;
    }

    char mem_dir[2048];
    snprintf(mem_dir, sizeof(mem_dir), "%s/memory", out_dir);
    if (mkdir(mem_dir, 0755) != 0 && errno != EEXIST) {
        if (cfg->verbose) {
            fprintf(stderr, "[debug] Failed to create memory directory '%s': %s\n", mem_dir, strerror(errno));
        }
        snprintf(stats.status, sizeof(stats.status), "FAILED");
        if (stats_out) *stats_out = stats;
        free(regions);
        return -1;
    }

    copy_maps_file(cfg->pid, out_dir);

    /* Open /proc/<pid>/mem if pread is used */
    char mem_path[128];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)cfg->pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (cfg->verbose) {
        fprintf(stderr, "[debug] open(%s) = %d (errno=%d: %s)\n", mem_path, mem_fd, errno, strerror(errno));
    }

    stats.capture_start_ns = get_time_ns();
    snprintf(stats.backend_used, sizeof(stats.backend_used), "%s",
             (cfg->backend == BACKEND_PROC_MEM) ? "pread" : "process_vm_readv");

    /* Allocate buffer for reading */
    size_t chunk_buf_size = 4 * 1024 * 1024; /* 4 MB initial buffer */
    void *buf = malloc(chunk_buf_size);
    if (!buf) {
        if (mem_fd >= 0) close(mem_fd);
        free(regions);
        return -1;
    }

    char manifest_path[2048];
    char manifest_tmp[2048];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", out_dir) >= (int)sizeof(manifest_path) ||
        snprintf(manifest_tmp, sizeof(manifest_tmp), "%s/manifest.json.tmp.%d", out_dir, (int)getpid()) >= (int)sizeof(manifest_tmp)) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
        if (mem_fd >= 0) close(mem_fd);
        free(buf);
        free(regions);
        if (stats_out) *stats_out = stats;
        return -1;
    }
    FILE *f_manifest = fopen(manifest_tmp, "w");
    if (!f_manifest) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
        if (mem_fd >= 0) close(mem_fd);
        free(buf);
        free(regions);
        if (stats_out) *stats_out = stats;
        return -1;
    }
    int manifest_write_fail = (fprintf(f_manifest, "[\n") < 0);

    int manifest_idx = 0;
    for (int i = 0; i < region_count; i++) {
        parsed_region_t *r = &regions[i];
        if (!r->is_selected) continue;

        /* Enforce timeout if configured */
        if (cfg->timeout_ms > 0) {
            int64_t now_ns = get_time_ns();
            int64_t elapsed_ms = (now_ns - stats.capture_start_ns) / 1000000LL;
            if (elapsed_ms >= (int64_t)cfg->timeout_ms) {
                stats.timed_out = 1;
                if (cfg->verbose) {
                    fprintf(stderr, "[debug] Timeout of %u ms reached during capture (elapsed: %lld ms)\n",
                            cfg->timeout_ms, (long long)elapsed_ms);
                }
                break;
            }
        }

        size_t to_read = (size_t)r->size;
        if (cfg->max_region_bytes > 0 && to_read > cfg->max_region_bytes) {
            to_read = cfg->max_region_bytes;
        }

        stats.bytes_requested += to_read;

        if (to_read > chunk_buf_size) {
            void *new_buf = realloc(buf, to_read);
            if (new_buf) {
                buf = new_buf;
                chunk_buf_size = to_read;
            } else {
                to_read = chunk_buf_size;
            }
        }

        /* Read region in 1MB chunks to ensure timeout enforcement during large region reads */
        const size_t step_limit = 1024 * 1024; /* 1 MB */
        size_t total_nread = 0;
        int read_error = 0;

        while (total_nread < to_read) {
            if (cfg->timeout_ms > 0) {
                int64_t now_ns = get_time_ns();
                int64_t elapsed_ms = (now_ns - stats.capture_start_ns) / 1000000LL;
                if (elapsed_ms >= (int64_t)cfg->timeout_ms) {
                    stats.timed_out = 1;
                    if (cfg->verbose) {
                        fprintf(stderr, "[debug] Timeout of %u ms reached during chunk read (elapsed: %lld ms)\n",
                                cfg->timeout_ms, (long long)elapsed_ms);
                    }
                    break;
                }
            }

            size_t step = to_read - total_nread;
            if (step > step_limit) {
                step = step_limit;
            }

            size_t chunk_nread = 0;
            int step_res = collector_read_region(cfg->pid, mem_fd, cfg->backend, r->start + total_nread, step, (char *)buf + total_nread, &chunk_nread);
            if (step_res < 0 || chunk_nread == 0) {
                read_error = 1;
                break;
            }
            total_nread += chunk_nread;
            if (chunk_nread < step) {
                /* Partial read inside chunk */
                break;
            }
        }

        if (cfg->verbose && manifest_idx < 3) {
            fprintf(stderr, "[debug] region 0x%llx-0x%llx to_read=%zu total_nread=%zu read_error=%d errno=%d (%s)\n",
                   (unsigned long long)r->start, (unsigned long long)r->end, to_read, total_nread, read_error, errno, strerror(errno));
        }

        manifest_idx++;
        char rel_bin_file[128];
        snprintf(rel_bin_file, sizeof(rel_bin_file), "memory/region_%06d.bin", manifest_idx);

        const char *status_str = "COMPLETE";
        const char *error_str = "null";
        char err_buf[64] = {0};

        if (total_nread == 0) {
            stats.failed_reads++;
            status_str = "FAILED";
            snprintf(err_buf, sizeof(err_buf), "\"EFAULT_OR_READ_ERROR\"");
            error_str = err_buf;
        } else {
            char full_bin_path[2048];
            int bin_err = 0;
            if (snprintf(full_bin_path, sizeof(full_bin_path), "%s/%s", out_dir, rel_bin_file) >= (int)sizeof(full_bin_path)) {
                bin_err = 1;
            } else {
                FILE *f_bin = fopen(full_bin_path, "wb");
                if (!f_bin) {
                    bin_err = 1;
                } else {
                    size_t nw = fwrite(buf, 1, total_nread, f_bin);
                    int wr_fail = (nw != total_nread || ferror(f_bin));
                    int cl_fail = (fclose(f_bin) != 0);
                    if (wr_fail || cl_fail) {
                        bin_err = 1;
                    }
                }
            }

            if (bin_err) {
                unlink(full_bin_path);
                stats.failed_reads++;
                status_str = "FAILED";
                snprintf(err_buf, sizeof(err_buf), "\"BIN_WRITE_FAILED\"");
                error_str = err_buf;
            } else if (total_nread < to_read) {
                stats.partial_reads++;
                stats.bytes_captured += total_nread;
                stats.regions_captured++;
                status_str = "PARTIAL";
                snprintf(err_buf, sizeof(err_buf), "\"PARTIAL_READ_%zu_OF_%zu\"", total_nread, to_read);
                error_str = err_buf;
            } else {
                stats.bytes_captured += total_nread;
                stats.regions_captured++;
                status_str = "COMPLETE";
                error_str = "null";
            }
        }

        if (f_manifest) {
            char esc_path[1024] = {0};
            escape_json_string(r->pathname, esc_path, sizeof(esc_path));

            if (fprintf(f_manifest, "%s    {\n", (manifest_idx > 1) ? ",\n" : "") < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"region_id\": \"R%06d\",\n", manifest_idx) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"start\": \"0x%llx\",\n", (unsigned long long)r->start) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"end\": \"0x%llx\",\n", (unsigned long long)r->end) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"start_addr\": %llu,\n", (unsigned long long)r->start) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"end_addr\": %llu,\n", (unsigned long long)r->end) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"size\": %llu,\n", (unsigned long long)r->size) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"permissions\": \"%s\",\n", r->perms) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"category\": \"%s\",\n", r->category) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"pathname\": \"%s\",\n", esc_path) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"requested\": %llu,\n", (unsigned long long)to_read) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"captured\": %llu,\n", (unsigned long long)((strcmp(status_str, "FAILED") == 0) ? 0 : total_nread)) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"status\": \"%s\",\n", status_str) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"filename\": \"%s\",\n", (strcmp(status_str, "FAILED") != 0 && total_nread > 0) ? rel_bin_file : "") < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "      \"error\": %s\n", error_str) < 0) manifest_write_fail = 1;
            if (fprintf(f_manifest, "    }") < 0) manifest_write_fail = 1;
        }

        if (stats.timed_out) {
            break;
        }
    }

    int manifest_err = 0;
    if (f_manifest) {
        if (fprintf(f_manifest, "\n  ]\n") < 0) manifest_write_fail = 1;
        int fr_err = (ferror(f_manifest) != 0);
        int cl_err = (fclose(f_manifest) != 0);
        if (manifest_write_fail || fr_err || cl_err) {
            manifest_err = 1;
            unlink(manifest_tmp);
        } else {
            if (rename(manifest_tmp, manifest_path) != 0) {
                manifest_err = 1;
                unlink(manifest_tmp);
            }
        }
    } else {
        manifest_err = 1;
    }

    stats.capture_end_ns = get_time_ns();
    stats.duration_us = (double)(stats.capture_end_ns - stats.capture_start_ns) / 1000.0;

    if (stats.timed_out) {
        snprintf(stats.status, sizeof(stats.status), (stats.regions_captured > 0) ? "PARTIAL" : "TIMEOUT");
    } else if (stats.failed_reads == stats.regions_requested && stats.regions_requested > 0) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
    } else if (stats.partial_reads > 0 || stats.failed_reads > 0) {
        snprintf(stats.status, sizeof(stats.status), "PARTIAL");
    } else {
        snprintf(stats.status, sizeof(stats.status), "COMPLETE");
    }

    /* Check process starttime after capture to detect PID recycling / exit */
    uint64_t starttime_after = 0;
    if (collector_get_process_starttime(cfg->pid, &starttime_after) < 0 || starttime_after != starttime_before) {
        stats.process_exited = 1;
        snprintf(stats.status, sizeof(stats.status), "PROCESS_EXITED");
    }

    /* Check maps after capture to detect concurrent mmap/munmap/mprotect race */
    parsed_region_t *regions_after = NULL;
    int region_count_after = 0;
    if (collector_parse_maps(cfg->pid, exe_path, &regions_after, &region_count_after) == 0) {
        int cmp = collector_compare_maps(regions, region_count, regions_after, region_count_after);
        if (cmp != 0) {
            stats.mapping_race_detected = 1;
            if (strcmp(stats.status, "PROCESS_EXITED") != 0) {
                snprintf(stats.status, sizeof(stats.status), "PARTIAL");
            }
        }
        free(regions_after);
    } else {
        stats.mapping_race_detected = 1;
        if (strcmp(stats.status, "PROCESS_EXITED") != 0) {
            snprintf(stats.status, sizeof(stats.status), "PARTIAL");
        }
    }

    /* Write maps.json atomically */
    char maps_json_path[2048];
    char maps_json_tmp[2048];
    int maps_err = 0;
    int maps_write_fail = 0;
    if (snprintf(maps_json_path, sizeof(maps_json_path), "%s/maps.json", out_dir) >= (int)sizeof(maps_json_path) ||
        snprintf(maps_json_tmp, sizeof(maps_json_tmp), "%s/maps.json.tmp.%d", out_dir, (int)getpid()) >= (int)sizeof(maps_json_tmp)) {
        maps_err = 1;
    } else {
        FILE *f_maps = fopen(maps_json_tmp, "w");
        if (!f_maps) {
            maps_err = 1;
        } else {
            if (fprintf(f_maps, "[\n") < 0) maps_write_fail = 1;
            for (int i = 0; i < region_count; i++) {
                parsed_region_t *r = &regions[i];
                char esc_path[1024] = {0};
                escape_json_string(r->pathname, esc_path, sizeof(esc_path));

                if (fprintf(f_maps, "%s    {\n", (i > 0) ? ",\n" : "") < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"start\": \"0x%llx\",\n", (unsigned long long)r->start) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"end\": \"0x%llx\",\n", (unsigned long long)r->end) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"start_addr\": %llu,\n", (unsigned long long)r->start) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"end_addr\": %llu,\n", (unsigned long long)r->end) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"size\": %llu,\n", (unsigned long long)r->size) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"permissions\": \"%s\",\n", r->perms) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"offset\": %llu,\n", (unsigned long long)r->offset) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"device\": \"%s\",\n", r->device) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"inode\": %llu,\n", (unsigned long long)r->inode) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"pathname\": \"%s\",\n", esc_path) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"readable\": %s,\n", r->readable ? "true" : "false") < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"writable\": %s,\n", r->writable ? "true" : "false") < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"executable\": %s,\n", r->executable ? "true" : "false") < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"category\": \"%s\",\n", r->category) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "      \"kind\": \"%s\"\n", r->category) < 0) maps_write_fail = 1;
                if (fprintf(f_maps, "    }") < 0) maps_write_fail = 1;
            }
            if (fprintf(f_maps, "\n  ]\n") < 0) maps_write_fail = 1;
            int fr_err = (ferror(f_maps) != 0);
            int cl_err = (fclose(f_maps) != 0);
            if (maps_write_fail || fr_err || cl_err) {
                maps_err = 1;
                unlink(maps_json_tmp);
            } else {
                if (rename(maps_json_tmp, maps_json_path) != 0) {
                    maps_err = 1;
                    unlink(maps_json_tmp);
                }
            }
        }
    }

    if (manifest_err || maps_err) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
    }

    /* Write metadata.json atomically as the final commit barrier */
    char meta_json_path[2048];
    char meta_json_tmp[2048];
    int meta_err = 0;
    int meta_write_fail = 0;
    if (snprintf(meta_json_path, sizeof(meta_json_path), "%s/metadata.json", out_dir) >= (int)sizeof(meta_json_path) ||
        snprintf(meta_json_tmp, sizeof(meta_json_tmp), "%s/metadata.json.tmp.%d", out_dir, (int)getpid()) >= (int)sizeof(meta_json_tmp)) {
        meta_err = 1;
    } else {
        FILE *f_meta = fopen(meta_json_tmp, "w");
        if (!f_meta) {
            meta_err = 1;
        } else {
            char esc_bin[1024] = {0};
            escape_json_string(exe_path, esc_bin, sizeof(esc_bin));
            const char *snap_id = cfg->snapshot_id[0] ? cfg->snapshot_id : "RAW_CAPTURE";
            int is_success = (strcmp(stats.status, "COMPLETE") == 0 || strcmp(stats.status, "PARTIAL") == 0);
            int is_committed = (!manifest_err && !maps_err && is_success);
            int64_t commit_ts = get_time_ns();

            if (fprintf(f_meta, "{\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"success\": %s,\n", is_success ? "true" : "false") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"committed\": %s,\n", is_committed ? "true" : "false") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"commit_timestamp_ns\": %lld,\n", (long long)commit_ts) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"snapshot_id\": \"%s\",\n", snap_id) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"pid\": %d,\n", (int)cfg->pid) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"binary\": \"%s\",\n", esc_bin) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"timestamp_ns\": %lld,\n", (long long)stats.capture_start_ns) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"capture_mode\": \"LOW_IMPACT_NATIVE_COLLECTOR\",\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"backend\": \"%s\",\n", stats.backend_used) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"architecture\": \"%s\",\n", stats.arch) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"endianness\": \"%s\",\n", stats.endianness) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"elf_class\": \"%s\",\n", stats.elf_class) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"page_size\": %ld,\n", stats.page_size) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"status\": \"%s\",\n", stats.status) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"timed_out\": %s,\n", stats.timed_out ? "true" : "false") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"timeout_ms\": %u,\n", cfg->timeout_ms) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"mapping_race_detected\": %s,\n", stats.mapping_race_detected ? "true" : "false") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"process_exited\": %s,\n", stats.process_exited ? "true" : "false") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"process_starttime\": %llu,\n", (unsigned long long)stats.process_starttime) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"capture\": {\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"backend\": \"%s\",\n", stats.backend_used) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"process_stop\": false,\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"ptrace\": false,\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"sigstop\": false,\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"sigcont\": false\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  },\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"regions\": %d,\n", stats.regions_captured) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"regions_requested\": %d,\n", stats.regions_requested) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"bytes_requested\": %zu,\n", stats.bytes_requested) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"bytes_captured\": %zu,\n", stats.bytes_captured) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"partial_reads\": %d,\n", stats.partial_reads) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"failed_reads\": %d,\n", stats.failed_reads) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"duration_us\": %.2f,\n", stats.duration_us) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"duration_ms\": %.3f,\n", stats.duration_us / 1000.0) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"capture_start_ns\": %lld,\n", (long long)stats.capture_start_ns) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"capture_end_ns\": %lld,\n", (long long)stats.capture_end_ns) < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"consistency\": {\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "    \"level\": \"NON_ATOMIC\"\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  },\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "  \"modules\": []\n") < 0) meta_write_fail = 1;
            if (fprintf(f_meta, "}\n") < 0) meta_write_fail = 1;

            int fr_err = (ferror(f_meta) != 0);
            int cl_err = (fclose(f_meta) != 0);
            if (meta_write_fail || fr_err || cl_err) {
                meta_err = 1;
                unlink(meta_json_tmp);
            } else {
                if (rename(meta_json_tmp, meta_json_path) != 0) {
                    meta_err = 1;
                    unlink(meta_json_tmp);
                }
            }
        }
    }

    if (manifest_err || maps_err || meta_err) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
        if (mem_fd >= 0) close(mem_fd);
        free(buf);
        free(regions);
        if (stats_out) *stats_out = stats;
        return -1;
    }

    if (mem_fd >= 0) close(mem_fd);
    free(buf);
    free(regions);

    if (stats_out) {
        *stats_out = stats;
    }
    return 0;
}

int collector_read_slices(pid_t pid, int backend, const char *slices_spec, void *out_file) {
    FILE *out = out_file ? (FILE *)out_file : stdout;
    if (pid <= 0 || !slices_spec || !slices_spec[0]) {
        fprintf(out, "{\"success\":false,\"error\":\"INVALID_ARGS\",\"pid\":%d}\n", (int)pid);
        fflush(out);
        return -1;
    }

    uint64_t st_before = 0;
    if (collector_get_process_starttime(pid, &st_before) < 0) {
        if (errno == EPERM || errno == EACCES) {
            fprintf(out, "{\"success\":false,\"error\":\"PERMISSION_DENIED\",\"pid\":%d}\n", (int)pid);
        } else {
            fprintf(out, "{\"success\":false,\"error\":\"TARGET_TERMINATED\",\"pid\":%d}\n", (int)pid);
        }
        fflush(out);
        return -1;
    }

    char mem_path[128];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)pid);
    int mem_fd = open(mem_path, O_RDONLY);

    int64_t t_start = get_time_ns();
    const char *backend_name = (backend == BACKEND_PROC_MEM) ? "pread" : "process_vm_readv";

    fprintf(out, "{\"success\":true,\"pid\":%d,\"backend\":\"%s\",\"slices\":[", (int)pid, backend_name);

    char *spec_copy = strdup(slices_spec);
    if (!spec_copy) {
        if (mem_fd >= 0) close(mem_fd);
        fprintf(out, "]}\n");
        fflush(out);
        return -1;
    }

    int slice_idx = 0;
    char *saveptr = NULL;
    char *token = strtok_r(spec_copy, ",", &saveptr);
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;
        char *colon = strchr(token, ':');
        if (colon) {
            *colon = '\0';
            const char *addr_str = token;
            const char *size_str = colon + 1;
            uint64_t addr = strtoull(addr_str, NULL, 0);
            size_t sz = (size_t)strtoull(size_str, NULL, 0);
            if (sz > 65536) sz = 65536;

            unsigned char *buf = (sz > 0) ? (unsigned char *)malloc(sz) : NULL;
            size_t nread = 0;
            int rc = -1;
            if (sz == 0) {
                rc = 0;
            } else if (buf) {
                rc = collector_read_region(pid, mem_fd, backend, addr, sz, buf, &nread);
            }

            const char *status = "UNAVAILABLE";
            if (rc == 0 && nread == sz) {
                status = "OBSERVED";
            } else if (rc == 0 && nread > 0) {
                status = "PARTIAL";
            } else {
                uint64_t st_check = 0;
                if (collector_get_process_starttime(pid, &st_check) < 0) {
                    status = "TARGET_TERMINATED";
                } else if (errno == EPERM || errno == EACCES) {
                    status = "PERMISSION_DENIED";
                }
            }

            fprintf(out, "%s{\"address\":\"0x%llx\",\"size\":%zu,\"bytes_read\":%zu,\"status\":\"%s\",\"hex\":\"",
                    (slice_idx > 0) ? "," : "",
                    (unsigned long long)addr, sz, nread, status);
            for (size_t b = 0; b < nread; b++) {
                fprintf(out, "%02x", buf[b]);
            }
            fprintf(out, "\"}");
            if (buf) free(buf);
            slice_idx++;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    free(spec_copy);
    if (mem_fd >= 0) close(mem_fd);

    int64_t t_end = get_time_ns();
    double dur_us = (double)(t_end - t_start) / 1000.0;
    fprintf(out, "],\"duration_us\":%.2f}\n", dur_us);
    fflush(out);
    return 0;
}

int collector_daemon_loop(int backend, void *in_file, void *out_file) {
    FILE *in = in_file ? (FILE *)in_file : stdin;
    FILE *out = out_file ? (FILE *)out_file : stdout;
    char line[8192];

    while (fgets(line, sizeof(line), in)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;

        if (strncmp(p, "QUIT", 4) == 0 || strncmp(p, "EXIT", 4) == 0) {
            fprintf(out, "{\"success\":true,\"status\":\"BYE\"}\n");
            fflush(out);
            break;
        }
        if (strncmp(p, "PING", 4) == 0) {
            fprintf(out, "{\"success\":true,\"status\":\"PONG\"}\n");
            fflush(out);
            continue;
        }
        if (strncmp(p, "READ ", 5) == 0) {
            char *rest = p + 5;
            while (*rest == ' ') rest++;
            char *space = strchr(rest, ' ');
            if (!space) {
                fprintf(out, "{\"success\":false,\"error\":\"MISSING_SLICES_SPEC\"}\n");
                fflush(out);
                continue;
            }
            *space = '\0';
            pid_t pid = (pid_t)atoi(rest);
            char *spec = space + 1;
            while (*spec == ' ') spec++;
            collector_read_slices(pid, backend, spec, out);
            continue;
        }
        fprintf(out, "{\"success\":false,\"error\":\"UNKNOWN_COMMAND\"}\n");
        fflush(out);
    }
    return 0;
}
