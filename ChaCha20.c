#include "ChaCha20.h"

#define rot(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QR(x, a, b, c, d)      \
    x[a] += x[b]; x[d] = rot(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rot(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rot(x[d] ^ x[a],  8); \
    x[c] += x[d]; x[b] = rot(x[b] ^ x[c],  7)

static void __chacha20_get_next_key_stream(
    struct ChaCha20 *ctx
){
    memcpy(ctx->keyStream, ctx->curState, 64);

    for(int i = 0; i < 10; i++){
        QR(ctx -> keyStream, 0, 4,  8, 12);
        QR(ctx -> keyStream, 1, 5,  9, 13);
        QR(ctx -> keyStream, 2, 6, 10, 14);
        QR(ctx -> keyStream, 3, 7, 11, 15);
        QR(ctx -> keyStream, 0, 5, 10, 15);
        QR(ctx -> keyStream, 1, 6, 11, 12);
        QR(ctx -> keyStream, 2, 7,  8, 13);
        QR(ctx -> keyStream, 3, 4,  9, 14);
    }

    for(int i = 0; i < 16; i++)
        ctx->keyStream[i] += ctx -> curState[i];

    (*(uint64_t*) &(ctx -> curState[12]))++;
}

#undef QR
#undef rot

struct ChaCha20* InitChaCha20(
        const uint8_t  *key,
        const uint8_t  *nonce,
        const uint64_t counter
){
    struct ChaCha20 *ctx = malloc(sizeof(struct ChaCha20));

    memcpy(&(ctx -> curState[0]), "expand 32-byte k", 16);
    memcpy(&(ctx -> curState[4]), key, 32);
    memset(&(ctx -> curState[12]), 0, 4);
    memcpy(&(ctx -> curState[13]), nonce, 12);
    *(uint64_t*) &(ctx -> curState[12]) += (uint64_t) counter;

    return ctx;
}

void ChaCha20XOR(
    struct ChaCha20 *ctx,
    uint8_t         *buf,
    const uint64_t  len
){
    for(int i = 0; i < len; i++){
        if((i & 0x3f) == 0){
            __chacha20_get_next_key_stream(ctx);
        }
        buf[i] ^= ((uint8_t*) ctx->keyStream)[i & 0x3f];
    }
}

#ifdef TEST
#undef TEST

#include <stdio.h>

int main(int argc, char **argv){
    struct ChaCha20 *ctx = InitChaCha20(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nnnnnnnnnnnn", 0);

    char *buf = malloc(320);
    buf[319] = 0;
    memcpy(buf,
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec"
        "quis erat in felis volutpat vestibulum eget auctor nisi. Cras"
        "mollis tincidunt mauris eu ultricies. Vivamus vitae ultricies"
        "dui. Phasellus cursus, nisl sit amet consequat pharetra, elit"
        "ipsum egestas sapien, eu sodales mi nisl id elit. Nulla ligula"
        "blandit",
        319) ;

    printf("%s\n", buf);

    ChaCha20XOR(ctx, buf, 319);

    printf("%s\n", buf);

    struct ChaCha20 *ctx2 = InitChaCha20(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "nnnnnnnnnnnn", 0);

    ChaCha20XOR(ctx2, buf, 319);

    printf("%s\n", buf);

    return 0;
}

#endif
