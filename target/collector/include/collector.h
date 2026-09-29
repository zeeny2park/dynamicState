#ifndef DYNAMICSTATE_COLLECTOR_H
#define DYNAMICSTATE_COLLECTOR_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Policy constants */
#define POLICY_ALL_READABLE 0
#define POLICY_HEAP_STACK    1
#define POLICY_WRITABLE      2

/* Snapshot backend */
#define BACKEND_AUTO         0
#define BACKEND_VM_READV     1
#define BACKEND_PROC_MEM     2

typedef struct {
    pid_t pid;
    char output_dir[1024];
    char snapshot_id[64];
    size_t max_total_bytes;
    size_t max_region_bytes;
    int policy;
    int backend;
    int verbose;
} collector_config_t;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t size;
    char perms[8];
    uint64_t offset;
    char device[32];
    uint64_t inode;
    char pathname[512];
    char category[32];
    int readable;
    int writable;
    int executable;
    int is_selected;
} parsed_region_t;

typedef struct {
    int regions_found;
    int regions_requested;
    int regions_captured;
    size_t bytes_requested;
    size_t bytes_captured;
    int partial_reads;
    int failed_reads;
    int64_t capture_start_ns;
    int64_t capture_end_ns;
    double duration_us;
    char status[32];          /* "COMPLETE", "PARTIAL", "FAILED" */
    char backend_used[32];    /* "process_vm_readv", "pread" */
    char arch[65];
    char endianness[16];
    char elf_class[16];
    long page_size;
} collector_stats_t;

void collector_init_config(collector_config_t *cfg);
int collector_get_exe_path(pid_t pid, char *buf, size_t buf_size);
int collector_parse_maps(pid_t pid, const char *exe_path, parsed_region_t **regions_out, int *count_out);
void collector_classify_region(parsed_region_t *r, const char *exe_path);
int collector_filter_regions(parsed_region_t *regions, int count, const collector_config_t *cfg, int *selected_count_out);
int collector_read_region(pid_t pid, int mem_fd, int backend, uint64_t start, size_t size, void *buf, size_t *bytes_read);
int collector_run(const collector_config_t *cfg, collector_stats_t *stats_out);

#ifdef __cplusplus
}
#endif

#endif /* DYNAMICSTATE_COLLECTOR_H */
