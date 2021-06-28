#ifndef FILEIO_H
#define FILEIO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include "ChaCha20.h"
#include "md4.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void encrypt(
    const char *ifile,
    const char *ofile,
    const uint32_t *key
);

extern void decrypt(
    const char *ifile,
    const char *ofile,
    const uint32_t *key
);

#ifdef __cplusplu
}
#endif

#endif
