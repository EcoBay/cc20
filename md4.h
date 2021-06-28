#ifndef MD4_H
#define MD4_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t* md4(
    const uint8_t *buf,
    const uint64_t len
);

#ifdef __cplusplus
}
#endif

#endif
