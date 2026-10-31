#ifndef DYNAMICSTATE_SHA256_H
#define DYNAMICSTATE_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[32]);
void sha256_hex(const void *data, size_t len, char hex_out[65]);
int sha256_file_fd(int fd, char hex_out[65]);

void hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len, uint8_t out[32]);
void hmac_sha256_hex(const void *key, size_t key_len, const void *data, size_t data_len, char hex_out[65]);

#ifdef __cplusplus
}
#endif

#endif /* DYNAMICSTATE_SHA256_H */
