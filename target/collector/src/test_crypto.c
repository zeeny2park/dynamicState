#include "../include/sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex2bin(const char *hex, uint8_t **out_bin, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t blen = hlen / 2;
    uint8_t *buf = (uint8_t *)malloc(blen > 0 ? blen : 1);
    if (!buf) return -1;
    for (size_t i = 0; i < blen; ++i) {
        unsigned int val = 0;
        if (sscanf(&hex[i * 2], "%02x", &val) != 1) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)val;
    }
    *out_bin = buf;
    *out_len = blen;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        printf("Usage:\n"
               "  %s --selftest\n"
               "  %s --sha256-hex <hex_data>\n"
               "  %s --hmac-hex <hex_key> <hex_data>\n",
               argv[0], argv[0], argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "--selftest") == 0) {
        int res = collector_crypto_selftest();
        if (res == 0) {
            printf("PASS: All FIPS 180-4 and RFC 4231 vectors validated in C.\n");
            return 0;
        } else {
            fprintf(stderr, "FAIL: Cryptographic self-test failed in C.\n");
            return 1;
        }
    }

    if (strcmp(argv[1], "--sha256-hex") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Missing hex data argument.\n");
            return 1;
        }
        uint8_t *bin = NULL;
        size_t blen = 0;
        if (hex2bin(argv[2], &bin, &blen) != 0) {
            fprintf(stderr, "Error: Invalid hex data.\n");
            return 1;
        }
        char hex_out[65];
        sha256_hex(bin, blen, hex_out);
        free(bin);
        printf("%s\n", hex_out);
        return 0;
    }

    if (strcmp(argv[1], "--hmac-hex") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Missing hex key or hex data argument.\n");
            return 1;
        }
        uint8_t *kbin = NULL, *dbin = NULL;
        size_t klen = 0, dlen = 0;
        if (hex2bin(argv[2], &kbin, &klen) != 0 || hex2bin(argv[3], &dbin, &dlen) != 0) {
            if (kbin) free(kbin);
            if (dbin) free(dbin);
            fprintf(stderr, "Error: Invalid hex key or data.\n");
            return 1;
        }
        char hex_out[65];
        hmac_sha256_hex(kbin, klen, dbin, dlen, hex_out);
        secure_memzero(kbin, klen);
        free(kbin);
        free(dbin);
        printf("%s\n", hex_out);
        return 0;
    }

    fprintf(stderr, "Unknown option: %s\n", argv[1]);
    return 1;
}
