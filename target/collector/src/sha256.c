#include "sha256.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>

/* SHA-256 implementation according to FIPS 180-4 */

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define SIGMA0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define SIGMA1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define SIG0(x)   (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define SIG1(x)   (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (int t = 0; t < 16; ++t) {
        w[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
        w[t] = SIG1(w[t - 2]) + w[t - 7] + SIG0(w[t - 15]) + w[t - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int t = 0; t < 64; ++t) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) + K[t] + w[t];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buffer_bytes = (size_t)(ctx->count % 64);
    ctx->count += len;

    if (buffer_bytes > 0) {
        size_t needed = 64 - buffer_bytes;
        if (len < needed) {
            memcpy(&ctx->buffer[buffer_bytes], p, len);
            return;
        }
        memcpy(&ctx->buffer[buffer_bytes], p, needed);
        sha256_transform(ctx, ctx->buffer);
        p += needed;
        len -= needed;
    }

    while (len >= 64) {
        sha256_transform(ctx, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, p, len);
    }
}

void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint64_t total_bits = ctx->count * 8;
    size_t buffer_bytes = (size_t)(ctx->count % 64);

    ctx->buffer[buffer_bytes++] = 0x80;
    if (buffer_bytes > 56) {
        memset(&ctx->buffer[buffer_bytes], 0, 64 - buffer_bytes);
        sha256_transform(ctx, ctx->buffer);
        buffer_bytes = 0;
    }
    memset(&ctx->buffer[buffer_bytes], 0, 56 - buffer_bytes);

    for (int i = 7; i >= 0; --i) {
        ctx->buffer[56 + (7 - i)] = (uint8_t)((total_bits >> (i * 8)) & 0xff);
    }
    sha256_transform(ctx, ctx->buffer);

    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
    }
}

void sha256_hex(const void *data, size_t len, char hex_out[65]) {
    sha256_ctx ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);

    for (int i = 0; i < 32; ++i) {
        sprintf(&hex_out[i * 2], "%02x", hash[i]);
    }
    hex_out[64] = '\0';
}

int sha256_file_fd(int fd, char hex_out[65]) {
    if (fd < 0) return -1;

    struct stat st;
    off_t expected_size = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        expected_size = st.st_size;
    }

    off_t orig = lseek(fd, 0, SEEK_SET);
    (void)orig;

    sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[8192];
    size_t total_read = 0;

    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            secure_memzero(buf, sizeof(buf));
            return -1;
        }
        if (n == 0) break;
        sha256_update(&ctx, buf, (size_t)n);
        total_read += (size_t)n;
    }
    secure_memzero(buf, sizeof(buf));

    if (expected_size >= 0 && (off_t)total_read != expected_size) {
        return -1;
    }

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i) {
        sprintf(&hex_out[i * 2], "%02x", hash[i]);
    }
    hex_out[64] = '\0';
    secure_memzero(hash, sizeof(hash));
    return 0;
}

/* HMAC-SHA256 implementation according to RFC 2104 */

void hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len, uint8_t out[32]) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));

    if (key_len > 64) {
        sha256_ctx kctx;
        sha256_init(&kctx);
        sha256_update(&kctx, key, key_len);
        sha256_final(&kctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    sha256_ctx ctx;
    /* Inner hash */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64);
    sha256_update(&ctx, data, data_len);
    uint8_t inner_hash[32];
    sha256_final(&ctx, inner_hash);

    /* Outer hash */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, out);

    /* Memory scrub sensitive keying material and intermediate states */
    secure_memzero(k, sizeof(k));
    secure_memzero(k_ipad, sizeof(k_ipad));
    secure_memzero(k_opad, sizeof(k_opad));
    secure_memzero(inner_hash, sizeof(inner_hash));
    secure_memzero(&ctx, sizeof(ctx));
}

void hmac_sha256_hex(const void *key, size_t key_len, const void *data, size_t data_len, char hex_out[65]) {
    uint8_t out[32];
    hmac_sha256(key, key_len, data, data_len, out);
    for (int i = 0; i < 32; ++i) {
        sprintf(&hex_out[i * 2], "%02x", out[i]);
    }
    hex_out[64] = '\0';
    secure_memzero(out, sizeof(out));
}

void secure_memzero(void *v, size_t n) {
    if (!v || n == 0) return;
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    explicit_bzero(v, n);
#else
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
#endif
}

int collector_crypto_selftest(void) {
    int failed = 0;
    char hex[65];

    /* 1. FIPS 180-4 SHA-256 Vector 1: Empty string */
    sha256_hex("", 0, hex);
    if (strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: FIPS 180-4 SHA-256 empty string mismatch: got %s\n", hex);
        failed++;
    }

    /* 2. FIPS 180-4 SHA-256 Vector 2: 'abc' */
    sha256_hex("abc", 3, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: FIPS 180-4 SHA-256 'abc' mismatch: got %s\n", hex);
        failed++;
    }

    /* 3. FIPS 180-4 SHA-256 Vector 3: 56-byte message */
    const char *msg56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256_hex(msg56, strlen(msg56), hex);
    if (strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: FIPS 180-4 SHA-256 56-byte message mismatch: got %s\n", hex);
        failed++;
    }

    /* 4. RFC 4231 HMAC-SHA256 Test Case 1 */
    uint8_t k1[20];
    memset(k1, 0x0b, sizeof(k1));
    hmac_sha256_hex(k1, sizeof(k1), "Hi There", 8, hex);
    if (strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 1 mismatch: got %s\n", hex);
        failed++;
    }

    /* 5. RFC 4231 HMAC-SHA256 Test Case 2 */
    hmac_sha256_hex("Jefe", 4, "what do ya want for nothing?", 28, hex);
    if (strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 2 mismatch: got %s\n", hex);
        failed++;
    }

    /* 6. RFC 4231 HMAC-SHA256 Test Case 3 */
    uint8_t k3[20], d3[50];
    memset(k3, 0xaa, sizeof(k3));
    memset(d3, 0xdd, sizeof(d3));
    hmac_sha256_hex(k3, sizeof(k3), d3, sizeof(d3), hex);
    if (strcmp(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 3 mismatch: got %s\n", hex);
        failed++;
    }

    /* 7. RFC 4231 HMAC-SHA256 Test Case 4 */
    uint8_t k4[25];
    for (int i = 0; i < 25; ++i) k4[i] = (uint8_t)(i + 1);
    uint8_t d4[50];
    memset(d4, 0xcd, sizeof(d4));
    hmac_sha256_hex(k4, sizeof(k4), d4, sizeof(d4), hex);
    if (strcmp(hex, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 4 mismatch: got %s\n", hex);
        failed++;
    }

    /* 8. RFC 4231 HMAC-SHA256 Test Case 5 (full 32-byte hash) */
    uint8_t k5[20];
    memset(k5, 0x0c, sizeof(k5));
    hmac_sha256_hex(k5, sizeof(k5), "Test With Truncation", 20, hex);
    if (strcmp(hex, "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 5 mismatch: got %s\n", hex);
        failed++;
    }

    /* 9. RFC 4231 HMAC-SHA256 Test Case 6 (key larger than 64-byte block size: 131 bytes) */
    uint8_t k6[131];
    memset(k6, 0xaa, sizeof(k6));
    const char *d6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256_hex(k6, sizeof(k6), d6, strlen(d6), hex);
    if (strcmp(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 6 mismatch: got %s\n", hex);
        failed++;
    }

    /* 10. RFC 4231 HMAC-SHA256 Test Case 7 (large key and large data) */
    const char *d7 = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    hmac_sha256_hex(k6, sizeof(k6), d7, strlen(d7), hex);
    if (strcmp(hex, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2") != 0) {
        fprintf(stderr, "Crypto SelfTest Failed: RFC 4231 HMAC Case 7 mismatch: got %s\n", hex);
        failed++;
    }

    /* 11. Binary input with embedded zeroes */
    const uint8_t binary_data[8] = {'A', 0x00, 'B', 0x00, 'C', 0x00, 'D', 0x00};
    sha256_hex(binary_data, sizeof(binary_data), hex);
    if (strlen(hex) != 64) {
        fprintf(stderr, "Crypto SelfTest Failed: binary data SHA-256 failed\n");
        failed++;
    }

    /* 12. Incorrect signature rejection */
    char wrong_sig[65];
    hmac_sha256_hex("wrong_secret_key_12345", 22, "Hi There", 8, wrong_sig);
    if (strcmp(hex, wrong_sig) == 0) {
        fprintf(stderr, "Crypto SelfTest Failed: different keys produced identical HMAC\n");
        failed++;
    }

    secure_memzero(k1, sizeof(k1));
    secure_memzero(k3, sizeof(k3));
    secure_memzero(k4, sizeof(k4));
    secure_memzero(k5, sizeof(k5));
    secure_memzero(k6, sizeof(k6));
    secure_memzero(hex, sizeof(hex));
    secure_memzero(wrong_sig, sizeof(wrong_sig));

    return (failed == 0) ? 0 : -1;
}
