#include "streebog.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "streebog_constants.h"

#define STREEBOG_ROUNDS 12

static void streebog_xor(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    for (size_t i = 0; i < STREEBOG_BLOCK_SIZE; ++i) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

static void streebog_add(const uint8_t* a, const uint8_t* b, uint8_t* out) {
    uint16_t carry = 0;
    for (size_t i = 0; i < STREEBOG_BLOCK_SIZE; ++i) {
        uint16_t sum = (uint16_t)a[i] + (uint16_t)b[i] + carry;
        out[i] = (uint8_t)(sum & 0xFFU);
        carry = sum >> 8;
    }
}

static void streebog_s(const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < STREEBOG_BLOCK_SIZE; ++i) {
        out[i] = STREEBOG_PI[in[STREEBOG_BLOCK_SIZE - 1U - i]];
    }
}

static void streebog_p(const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < STREEBOG_BLOCK_SIZE; ++i) {
        out[i] = in[STREEBOG_TAU[STREEBOG_BLOCK_SIZE - 1U - i]];
    }
}

static void streebog_l(const uint8_t* in, uint8_t* out) {
    memset(out, 0, STREEBOG_BLOCK_SIZE);
    for (int i = 7; i >= 0; --i) {
        for (int n = 0; n < 8; ++n) {
            int p = 63;
            uint8_t* target = &out[i * 8 + n];
            for (int j = 7; j >= 0; --j) {
                uint8_t byte = in[i * 8 + j];
                for (int k = 0; k < 8; ++k) {
                    if ((byte >> k) & 0x01U) {
                        *target ^= STREEBOG_L[(size_t)p * 8 + (size_t)n];
                    }
                    --p;
                }
            }
        }
    }
}

static void streebog_spl(uint8_t* state) {
    uint8_t tmp1[STREEBOG_BLOCK_SIZE];
    uint8_t tmp2[STREEBOG_BLOCK_SIZE];
    streebog_s(state, tmp1);
    streebog_p(tmp1, tmp2);
    streebog_l(tmp2, state);
}

static void streebog_e(const uint8_t* key, const uint8_t* m, uint8_t* out) {
    uint8_t state[STREEBOG_BLOCK_SIZE];
    uint8_t round_key[STREEBOG_BLOCK_SIZE];
    streebog_xor(key, m, state);
    memcpy(round_key, key, STREEBOG_BLOCK_SIZE);

    for (int i = 0; i < STREEBOG_ROUNDS; ++i) {
        streebog_spl(state);
        streebog_xor(round_key, &STREEBOG_C[i * STREEBOG_BLOCK_SIZE], round_key);
        streebog_spl(round_key);
        streebog_xor(round_key, state, state);
    }

    memcpy(out, state, STREEBOG_BLOCK_SIZE);
}

static void streebog_gN(const uint8_t* N, const uint8_t* h, const uint8_t* m, uint8_t* out) {
    uint8_t K[STREEBOG_BLOCK_SIZE];
    uint8_t t[STREEBOG_BLOCK_SIZE];
    uint8_t result[STREEBOG_BLOCK_SIZE];

    streebog_xor(h, N, K);
    streebog_spl(K);
    streebog_e(K, m, t);
    streebog_xor(t, h, result);
    streebog_xor(result, m, out);
}

void streebog_hash(const uint8_t* data, size_t len, uint8_t digest[STREEBOG_DIGEST_LENGTH]) {
    uint8_t h[STREEBOG_BLOCK_SIZE] = {0};
    uint8_t N[STREEBOG_BLOCK_SIZE] = {0};
    uint8_t Sigma[STREEBOG_BLOCK_SIZE] = {0};
    uint8_t v512[STREEBOG_BLOCK_SIZE] = {0};
    uint8_t zero_block[STREEBOG_BLOCK_SIZE] = {0};
    uint8_t block[STREEBOG_BLOCK_SIZE];
    uint8_t new_h[STREEBOG_BLOCK_SIZE];

    v512[1] = 0x02U;

    size_t remaining = len;
    while (remaining >= STREEBOG_BLOCK_SIZE) {
        size_t offset = remaining - STREEBOG_BLOCK_SIZE;
        memcpy(block, data + offset, STREEBOG_BLOCK_SIZE);
        streebog_gN(N, h, block, new_h);
        memcpy(h, new_h, STREEBOG_BLOCK_SIZE);
        streebog_add(N, v512, N);
        streebog_add(Sigma, block, Sigma);
        remaining -= STREEBOG_BLOCK_SIZE;
    }

    memset(block, 0, STREEBOG_BLOCK_SIZE);
    if (remaining > 0) {
        memcpy(block + (STREEBOG_BLOCK_SIZE - remaining), data, remaining);
    }
    block[STREEBOG_BLOCK_SIZE - 1] = 0x01U;
    streebog_gN(N, h, block, new_h);
    memcpy(h, new_h, STREEBOG_BLOCK_SIZE);

    uint8_t len_block[STREEBOG_BLOCK_SIZE] = {0};
    uint32_t bit_len = (uint32_t)(remaining * 8U);
    len_block[60] = (uint8_t)(bit_len & 0xFFU);
    len_block[61] = (uint8_t)((bit_len >> 8) & 0xFFU);
    len_block[62] = (uint8_t)((bit_len >> 16) & 0xFFU);
    len_block[63] = (uint8_t)((bit_len >> 24) & 0xFFU);

    streebog_add(N, len_block, N);
    streebog_add(Sigma, block, Sigma);

    streebog_gN(zero_block, h, N, new_h);
    memcpy(h, new_h, STREEBOG_BLOCK_SIZE);
    streebog_gN(zero_block, h, Sigma, new_h);
    memcpy(h, new_h, STREEBOG_BLOCK_SIZE);
    memcpy(digest, h, STREEBOG_DIGEST_LENGTH);
}
