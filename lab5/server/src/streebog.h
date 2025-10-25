#ifndef SRC_STREEBOG_H
#define SRC_STREEBOG_H

#include <stddef.h>
#include <stdint.h>

#define STREEBOG_BLOCK_SIZE 64U
#define STREEBOG_DIGEST_LENGTH 64U

void streebog_hash(const uint8_t* data, size_t len, uint8_t digest[STREEBOG_DIGEST_LENGTH]);

#endif
