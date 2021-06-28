#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ChaCha20{
    uint32_t keyStream[16];
    uint32_t curState[16];
};

extern struct ChaCha20* InitChaCha20(
    const uint8_t  *key,
    const uint8_t  *nonce,
    const uint64_t counter
);

extern void ChaCha20XOR(
    struct ChaCha20 *ctx,
    uint8_t         *buf,
    const uint64_t  len
);

#ifdef __cplusplus
}
#endif

#endif
