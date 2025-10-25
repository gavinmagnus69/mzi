#ifndef SHA1_H
#define SHA1_H


#include <stddef.h>
#include <stdint.h>
#include <string.h>


#define SHA1_DIGEST_LENGTH 20U


void sha1_hash(const uint8_t* data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]);
#endif