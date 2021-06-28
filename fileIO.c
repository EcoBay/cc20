#include "fileIO.h"

const uint8_t *constMessage = "Encoded using github.com/EcoBay/cc20";

static void loadFileDescriptor(
    FILE **iF, FILE **oF, const char *ifile, const char *ofile
){
    if(!strcmp(ifile, "-")) *iF = stdout;
    else *iF = fopen(ifile, "r");
    if(!*iF){
        fprintf(stderr, "[Error] \"%s\" doesn't exist.\n", ifile);
        exit(EXIT_FAILURE);
    }

    if(!strcmp(ofile, "-")) *oF = stdout;
    else{
        if(!access(ofile, F_OK)){
            fprintf(stderr,
                "Output file already exists are "
                "you sure you want to overwrite? [Y/n] ");
            char c;
            scanf(" %c", &c);
            if (c == 'n' || c == 'N') exit(EXIT_SUCCESS);
            else if (c != 'y' && c != 'Y'){
                fprintf(stderr, "Invalid response.\n");
                exit(EXIT_FAILURE);
            }
        }
        *oF = fopen(ofile, "w+");
    }
}

void encrypt(
    const char *ifile, const char *ofile, const uint32_t *key
){
    FILE *iF, *oF;
    loadFileDescriptor(&iF, &oF, ifile, ofile);

    FILE *rng = fopen("/dev/urandom", "r");
    if(!rng){
        fprintf(stderr, "Cannot open \"/dev/urandom\"");
        exit(EXIT_FAILURE);
    }

    uint8_t *nonce = malloc(12);
    fread(nonce, 1, 12, rng);
    if(fclose(rng) == EOF) exit(EXIT_FAILURE);

    struct ChaCha20 *ctx = InitChaCha20(*(uint8_t **) &key, nonce, 0);

    fwrite(constMessage, 1, 36, oF);
    fwrite(nonce, 1, 12, oF);

    uint32_t *hkey = md4((uint8_t*)key, 32);
    fwrite(hkey, 4, 4, oF);

    uint8_t *buf = malloc(64);
    while(!feof(iF)){
        size_t l = fread(buf, 1, 64, iF);
        if(ferror(iF)){
            fprintf(stderr, "Error reading input file\n");
            exit(EXIT_FAILURE);
        }
        ChaCha20XOR(ctx, buf, l);
        fwrite(buf, 1, l, oF);
        if(ferror(oF)){
            fprintf(stderr, "Error writing output file\n");
            exit(EXIT_FAILURE);
        }
    }

    if(fclose(iF) == EOF) exit(EXIT_FAILURE);
    if(fclose(oF) == EOF) exit(EXIT_FAILURE);
    free(ctx);
    free(buf);
}

void decrypt(
    const char *ifile, const char *ofile, const uint32_t *key
){
    FILE *iF, *oF;
    loadFileDescriptor(&iF, &oF, ifile, ofile);

    uint8_t *buf = malloc(64);
    fread(buf, 1, 36, iF);
    if(memcmp(buf, constMessage, 36)){
        fprintf(stderr, "Encrypted file not supported\n");
        exit(EXIT_FAILURE);
    }

    uint8_t *nonce = malloc(12);
    fread(nonce, 1, 12, iF);

    uint32_t *hkey = md4((uint8_t*) key, 32);
    uint32_t *rhkey = malloc(16);
    fread(rhkey, 4, 4, iF);
    if(memcmp(hkey, rhkey, 16)){
        fprintf(stderr, "Incorrect password or key\n");
        exit(EXIT_FAILURE);
    }
    free(rhkey); free(hkey);

    struct ChaCha20 *ctx = InitChaCha20(*(uint8_t **) &key, nonce, 0);
    free(nonce);

    while(!feof(iF)){
        size_t l = fread(buf, 1, 64, iF);
        if(ferror(iF)){
            fprintf(stderr, "Error reading input file\n");
            exit(EXIT_FAILURE);
        }
        ChaCha20XOR(ctx, buf, l);
        fwrite(buf, 1, l, oF);
        if(ferror(oF)){
            fprintf(stderr, "Error writing output file\n");
            exit(EXIT_FAILURE);
        }
    }

    if(fclose(iF) == EOF) exit(EXIT_FAILURE);
    if(fclose(oF) == EOF) exit(EXIT_FAILURE);
    free(ctx);
    free(buf);
}

#ifdef TEST
#undef TEST

int main(int argc, char **argv){
    uint32_t key[] = {
        0x41414141, 0x41414141, 0x41414141, 0x41414141, 
        0x41414141, 0x41414141, 0x41414141, 0x41414141
    };

    encrypt("plaintextorig", "ciphertext", key);
    decrypt("ciphertext", "plaintext", key);

    return 0;
}

#endif
