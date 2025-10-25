#ifndef SRC_SHA1_C
#define SRC_SHA1_C


#include "sha1.h"

#define SHA1_BLOCK_SIZE 64U


typedef struct sha1_ctx {
    uint32_t state[5];
    uint64_t bitcount;
    uint8_t buffer[SHA1_BLOCK_SIZE];
} sha1_ctx;


static uint32_t rotl32(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32U - bits));
}


static void sha1_process_block(sha1_ctx* ctx, const uint8_t block[SHA1_BLOCK_SIZE]) {
    uint32_t w[80];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) | ((uint32_t)block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 80; ++i) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    for (size_t i = 0; i < 80; ++i) {
        uint32_t f;
        uint32_t k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}


static void sha1_init(sha1_ctx* ctx) {
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}


static void sha1_update(sha1_ctx* ctx, const uint8_t* data, size_t len) {
    size_t buffer_offset = (size_t)(ctx->bitcount >> 3) % SHA1_BLOCK_SIZE;
    ctx->bitcount += (uint64_t)len * 8U;
    size_t bytes_to_fill = SHA1_BLOCK_SIZE - buffer_offset;
    size_t used = 0;
    if (buffer_offset && len >= bytes_to_fill) {
        memcpy(ctx->buffer + buffer_offset, data, bytes_to_fill);
        sha1_process_block(ctx, ctx->buffer);
        used += bytes_to_fill;
        buffer_offset = 0;
    }
    while (used + SHA1_BLOCK_SIZE <= len) {
        sha1_process_block(ctx, data + used);
        used += SHA1_BLOCK_SIZE;
    }
    if (used < len) {
        memcpy(ctx->buffer + buffer_offset, data + used, len - used);
    }
}


static void sha1_final(sha1_ctx* ctx, uint8_t digest[SHA1_DIGEST_LENGTH]) {
    uint8_t padding[SHA1_BLOCK_SIZE] = {0x80};
    uint8_t length_bytes[8];
    for (size_t i = 0; i < 8; ++i) {
        length_bytes[7 - i] = (uint8_t)((ctx->bitcount >> (i * 8)) & 0xFFU);
    }
    size_t buffer_offset = (size_t)(ctx->bitcount >> 3) % SHA1_BLOCK_SIZE;
    size_t padding_len = (buffer_offset < 56) ? (56 - buffer_offset) : (120 - buffer_offset);
    sha1_update(ctx, padding, padding_len);
    sha1_update(ctx, length_bytes, sizeof(length_bytes));
    for (size_t i = 0; i < 5; ++i) {
        digest[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xFFU);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFFU);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFFU);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFFU);
    }
}


void sha1_hash(const uint8_t* data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

#endif
