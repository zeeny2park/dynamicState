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
            strcmp(r->pathname, "[vsyscall]") == 0) {
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

static void copy_maps_file(pid_t pid, const char *dest_dir) {
    char src[128], dst[2048];
    snprintf(src, sizeof(src), "/proc/%d/maps", (int)pid);
    snprintf(dst, sizeof(dst), "%s/maps.txt", dest_dir);

    FILE *in = fopen(src, "r");
    if (!in) return;
    FILE *out = fopen(dst, "w");
    if (!out) {
        fclose(in);
        return;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) break;
    }
    fclose(in);
    fclose(out);
}

int collector_run(const collector_config_t *cfg, collector_stats_t *stats_out) {
    if (!cfg || cfg->pid <= 0) return -1;

    collector_stats_t stats;
    memset(&stats, 0, sizeof(stats));
    stats.page_size = sysconf(_SC_PAGESIZE);

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
    mkdir(out_dir, 0755);

    char mem_dir[2048];
    snprintf(mem_dir, sizeof(mem_dir), "%s/memory", out_dir);
    mkdir(mem_dir, 0755);

    copy_maps_file(cfg->pid, out_dir);

    /* Open /proc/<pid>/mem if pread is used */
    char mem_path[128];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)cfg->pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (cfg->verbose) {
        printf("[debug] open(%s) = %d (errno=%d: %s)\n", mem_path, mem_fd, errno, strerror(errno));
    }

    stats.capture_start_ns = get_time_ns();
    snprintf(stats.backend_used, sizeof(stats.backend_used), "%s",
             (cfg->backend == BACKEND_PROC_MEM) ? "pread" : "process_vm_readv");

    /* Allocate buffer for reading */
    size_t chunk_buf_size = 4 * 1024 * 1024; /* 4 MB buffer */
    void *buf = malloc(chunk_buf_size);
    if (!buf) {
        if (mem_fd >= 0) close(mem_fd);
        free(regions);
        return -1;
    }

    char manifest_path[2048];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", out_dir);
    FILE *f_manifest = fopen(manifest_path, "w");
    if (f_manifest) {
        fprintf(f_manifest, "[\n");
    }

    int manifest_idx = 0;
    for (int i = 0; i < region_count; i++) {
        parsed_region_t *r = &regions[i];
        if (!r->is_selected) continue;

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

        size_t nread = 0;
        int res = collector_read_region(cfg->pid, mem_fd, cfg->backend, r->start, to_read, buf, &nread);
        if (cfg->verbose && manifest_idx < 3) {
            printf("[debug] region 0x%lx-0x%lx to_read=%zu res=%d nread=%zu errno=%d (%s)\n",
                   (unsigned long)r->start, (unsigned long)r->end, to_read, res, nread, errno, strerror(errno));
        }

        manifest_idx++;
        char rel_bin_file[128];
        snprintf(rel_bin_file, sizeof(rel_bin_file), "memory/region_%06d.bin", manifest_idx);

        const char *status_str = "COMPLETE";
        const char *error_str = "null";
        char err_buf[64] = {0};

        if (res < 0 || nread == 0) {
            stats.failed_reads++;
            status_str = "FAILED";
            snprintf(err_buf, sizeof(err_buf), "\"EFAULT_OR_READ_ERROR\"");
            error_str = err_buf;
        } else if (nread < to_read) {
            stats.partial_reads++;
            stats.bytes_captured += nread;
            stats.regions_captured++;
            status_str = "PARTIAL";
            snprintf(err_buf, sizeof(err_buf), "\"PARTIAL_READ_%zu_OF_%zu\"", nread, to_read);
            error_str = err_buf;

            char full_bin_path[2048];
            snprintf(full_bin_path, sizeof(full_bin_path), "%s/%s", out_dir, rel_bin_file);
            FILE *f_bin = fopen(full_bin_path, "wb");
            if (f_bin) {
                fwrite(buf, 1, nread, f_bin);
                fclose(f_bin);
            }
        } else {
            stats.bytes_captured += nread;
            stats.regions_captured++;
            status_str = "COMPLETE";
            error_str = "null";

            char full_bin_path[2048];
            snprintf(full_bin_path, sizeof(full_bin_path), "%s/%s", out_dir, rel_bin_file);
            FILE *f_bin = fopen(full_bin_path, "wb");
            if (f_bin) {
                fwrite(buf, 1, nread, f_bin);
                fclose(f_bin);
            }
        }

        if (f_manifest) {
            char esc_path[1024] = {0};
            escape_json_string(r->pathname, esc_path, sizeof(esc_path));

            fprintf(f_manifest, "%s    {\n", (manifest_idx > 1) ? ",\n" : "");
            fprintf(f_manifest, "      \"region_id\": \"R%06d\",\n", manifest_idx);
            fprintf(f_manifest, "      \"start\": \"0x%lx\",\n", (unsigned long)r->start);
            fprintf(f_manifest, "      \"end\": \"0x%lx\",\n", (unsigned long)r->end);
            fprintf(f_manifest, "      \"start_addr\": %lu,\n", (unsigned long)r->start);
            fprintf(f_manifest, "      \"end_addr\": %lu,\n", (unsigned long)r->end);
            fprintf(f_manifest, "      \"size\": %lu,\n", (unsigned long)r->size);
            fprintf(f_manifest, "      \"permissions\": \"%s\",\n", r->perms);
            fprintf(f_manifest, "      \"category\": \"%s\",\n", r->category);
            fprintf(f_manifest, "      \"pathname\": \"%s\",\n", esc_path);
            fprintf(f_manifest, "      \"requested\": %lu,\n", (unsigned long)to_read);
            fprintf(f_manifest, "      \"captured\": %lu,\n", (unsigned long)nread);
            fprintf(f_manifest, "      \"status\": \"%s\",\n", status_str);
            fprintf(f_manifest, "      \"filename\": \"%s\",\n", (nread > 0) ? rel_bin_file : "");
            fprintf(f_manifest, "      \"error\": %s\n", error_str);
            fprintf(f_manifest, "    }");
        }
    }

    if (f_manifest) {
        fprintf(f_manifest, "\n  ]\n");
        fclose(f_manifest);
    }

    stats.capture_end_ns = get_time_ns();
    stats.duration_us = (double)(stats.capture_end_ns - stats.capture_start_ns) / 1000.0;

    if (stats.failed_reads == stats.regions_requested && stats.regions_requested > 0) {
        snprintf(stats.status, sizeof(stats.status), "FAILED");
    } else if (stats.partial_reads > 0 || stats.failed_reads > 0) {
        snprintf(stats.status, sizeof(stats.status), "PARTIAL");
    } else {
        snprintf(stats.status, sizeof(stats.status), "COMPLETE");
    }

    /* Write maps.json */
    char maps_json_path[2048];
    snprintf(maps_json_path, sizeof(maps_json_path), "%s/maps.json", out_dir);
    FILE *f_maps = fopen(maps_json_path, "w");
    if (f_maps) {
        fprintf(f_maps, "[\n");
        for (int i = 0; i < region_count; i++) {
            parsed_region_t *r = &regions[i];
            char esc_path[1024] = {0};
            escape_json_string(r->pathname, esc_path, sizeof(esc_path));

            fprintf(f_maps, "%s    {\n", (i > 0) ? ",\n" : "");
            fprintf(f_maps, "      \"start\": \"0x%lx\",\n", (unsigned long)r->start);
            fprintf(f_maps, "      \"end\": \"0x%lx\",\n", (unsigned long)r->end);
            fprintf(f_maps, "      \"start_addr\": %lu,\n", (unsigned long)r->start);
            fprintf(f_maps, "      \"end_addr\": %lu,\n", (unsigned long)r->end);
            fprintf(f_maps, "      \"size\": %lu,\n", (unsigned long)r->size);
            fprintf(f_maps, "      \"permissions\": \"%s\",\n", r->perms);
            fprintf(f_maps, "      \"offset\": %lu,\n", (unsigned long)r->offset);
            fprintf(f_maps, "      \"device\": \"%s\",\n", r->device);
            fprintf(f_maps, "      \"inode\": %lu,\n", (unsigned long)r->inode);
            fprintf(f_maps, "      \"pathname\": \"%s\",\n", esc_path);
            fprintf(f_maps, "      \"readable\": %s,\n", r->readable ? "true" : "false");
            fprintf(f_maps, "      \"writable\": %s,\n", r->writable ? "true" : "false");
            fprintf(f_maps, "      \"executable\": %s,\n", r->executable ? "true" : "false");
            fprintf(f_maps, "      \"category\": \"%s\",\n", r->category);
            fprintf(f_maps, "      \"kind\": \"%s\"\n", r->category);
            fprintf(f_maps, "    }");
        }
        fprintf(f_maps, "\n  ]\n");
        fclose(f_maps);
    }

    /* Write metadata.json */
    char meta_json_path[2048];
    snprintf(meta_json_path, sizeof(meta_json_path), "%s/metadata.json", out_dir);
    FILE *f_meta = fopen(meta_json_path, "w");
    if (f_meta) {
        char esc_bin[1024] = {0};
        escape_json_string(exe_path, esc_bin, sizeof(esc_bin));
        const char *snap_id = cfg->snapshot_id[0] ? cfg->snapshot_id : "RAW_CAPTURE";

        fprintf(f_meta, "{\n");
        fprintf(f_meta, "  \"snapshot_id\": \"%s\",\n", snap_id);
        fprintf(f_meta, "  \"pid\": %d,\n", (int)cfg->pid);
        fprintf(f_meta, "  \"binary\": \"%s\",\n", esc_bin);
        fprintf(f_meta, "  \"timestamp_ns\": %lld,\n", (long long)stats.capture_start_ns);
        fprintf(f_meta, "  \"capture_mode\": \"LOW_IMPACT_NATIVE_COLLECTOR\",\n");
        fprintf(f_meta, "  \"backend\": \"%s\",\n", stats.backend_used);
        fprintf(f_meta, "  \"architecture\": \"%s\",\n", stats.arch);
        fprintf(f_meta, "  \"endianness\": \"%s\",\n", stats.endianness);
        fprintf(f_meta, "  \"elf_class\": \"%s\",\n", stats.elf_class);
        fprintf(f_meta, "  \"page_size\": %ld,\n", stats.page_size);
        fprintf(f_meta, "  \"status\": \"%s\",\n", stats.status);
        fprintf(f_meta, "  \"capture\": {\n");
        fprintf(f_meta, "    \"backend\": \"%s\",\n", stats.backend_used);
        fprintf(f_meta, "    \"process_stop\": false,\n");
        fprintf(f_meta, "    \"ptrace\": false,\n");
        fprintf(f_meta, "    \"sigstop\": false,\n");
        fprintf(f_meta, "    \"sigcont\": false\n");
        fprintf(f_meta, "  },\n");
        fprintf(f_meta, "  \"regions\": %d,\n", stats.regions_captured);
        fprintf(f_meta, "  \"regions_requested\": %d,\n", stats.regions_requested);
        fprintf(f_meta, "  \"bytes_requested\": %zu,\n", stats.bytes_requested);
        fprintf(f_meta, "  \"bytes_captured\": %zu,\n", stats.bytes_captured);
        fprintf(f_meta, "  \"partial_reads\": %d,\n", stats.partial_reads);
        fprintf(f_meta, "  \"failed_reads\": %d,\n", stats.failed_reads);
        fprintf(f_meta, "  \"duration_us\": %.2f,\n", stats.duration_us);
        fprintf(f_meta, "  \"duration_ms\": %.3f,\n", stats.duration_us / 1000.0);
        fprintf(f_meta, "  \"capture_start_ns\": %lld,\n", (long long)stats.capture_start_ns);
        fprintf(f_meta, "  \"capture_end_ns\": %lld,\n", (long long)stats.capture_end_ns);
        fprintf(f_meta, "  \"consistency\": {\n");
        fprintf(f_meta, "    \"level\": \"NON_ATOMIC\"\n");
        fprintf(f_meta, "  },\n");
        fprintf(f_meta, "  \"modules\": []\n");
        fprintf(f_meta, "}\n");
        fclose(f_meta);
    }

    if (mem_fd >= 0) close(mem_fd);
    free(buf);
    free(regions);

    if (stats_out) {
        *stats_out = stats;
    }
    return 0;
}
