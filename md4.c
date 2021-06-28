#include "md4.h"

static inline uint32_t rot(uint32_t x, uint8_t n){
    return x << n | x >> 32 - n;
}

static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z){
    return x & y | ~x & z;
}

static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z){
    return x & y | x & z | y & z;
}

static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z){
    return x ^ y ^ z;
}

uint32_t* md4(
    const uint8_t *msg,
    const uint64_t msgLen
){
    uint32_t *h0 = malloc(4 * sizeof(uint32_t));
    h0[0] = 0x67452301;
    h0[1] = 0xEFCDAB89;
    h0[2] = 0x98BADCFE;
    h0[3] = 0x10325476;

    uint64_t len = msgLen + 72 & ~63ull;
    uint8_t *buf = malloc(len);
    memcpy(buf, msg, msgLen);
    memset(&buf[msgLen + 1], 0, len - msgLen - 9);
    buf[msgLen] = 0x80;
    *(uint64_t*) &buf[len - 8] = msgLen << 3;

    const uint8_t X1[] = {3, 7, 11, 19};
    const uint8_t X2[] = {3, 5, 9, 13};
    const uint8_t X3[] = {3, 9, 11, 15};
    const uint8_t K3[] = {
        0, 8, 4, 12,
        2, 10, 6, 14,
        1, 9, 5, 13,
        3, 11, 7, 15
    };

    for(int i = 0; i < len >> 6; i++){
        uint32_t *h = malloc(4 * sizeof(uint32_t));
        memcpy(h, h0, 4 * sizeof(uint32_t));

        uint32_t *X = malloc(16 * sizeof(uint32_t));
        memcpy(X, &buf[i * 64], 16 * sizeof(uint32_t));


#define mapping(x) uint8_t a = -(x) & 3;\
    uint8_t b = -(x) + 1 & 3;\
    uint8_t c = -(x) + 2 & 3;\
    uint8_t d = -(x) + 3 & 3

        for(int j = 0; j < 16; j++){
            mapping(j);
            uint32_t hn = h[a] + F(h[b], h[c], h[d]) + X[j];
            h[a] = rot(hn, X1[j & 3]);
        }

        for(int j = 0; j < 16; j++){
            mapping(j);
            uint32_t hn = h[a] + G(h[b], h[c], h[d]) + X[
                ((j & 3) << 2) + (j >> 2)] + 0x5A827999;
            h[a] = rot(hn, X2[j & 3]);
        }


        for(int j = 0; j < 16; j++){
            mapping(j);
            uint32_t hn = h[a] + H(h[b], h[c], h[d]) +
                X[K3[j]] + 0x6ED9EBA1;
            h[a] = rot(hn, X3[j & 3]);
        }

#undef mapping

        for(int j = 0; j < 4; j++)
            h0[j] += h[j];

        free(h); free(X);
    }

    free(buf);
    return h0;
}

#ifdef TEST
#undef TEST

#include <stdio.h>

int main(int argc, char **argv){
    char msg[] = "The quick brown fox jumps over the lazy dog";
    uint32_t *h = md4(msg, strlen(msg));
    printf("0x");
    for(int i = 3; i >= 0; i--)
        printf("%8x", h[i]);
    putchar('\n');
    return 0;
}

#endif
