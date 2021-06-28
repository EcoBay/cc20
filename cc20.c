#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <termios.h>

#include "fileIO.h"
#include "md4.h"

inline static uint32_t *passToKey(const char *pas, const uint64_t len){
    uint32_t *key = malloc(32);
    uint32_t *hash = md4(pas, len);
    memcpy(key, hash, 16);

    char *pasWithHash = malloc(len + 16);
    strcpy(pasWithHash, pas);
    memcpy(&pasWithHash[len], hash, 16);
    free(hash);

    hash = md4(pasWithHash, len + 16);
    free(pasWithHash);
    memcpy(&key[4], hash, 16);
    free(hash);

    return key;
}

inline static uint32_t *pass(){
    struct termios p;

    FILE *tty = fopen("/dev/tty", "r");
    if(!tty) exit(EXIT_FAILURE);

    if (tcgetattr(fileno(tty), &p)) exit(EXIT_FAILURE);
    p.c_lflag &= ~ECHO;
    if (tcsetattr(fileno(tty), TCSAFLUSH, &p)) exit(EXIT_FAILURE);

    fprintf(stderr, "Enter password: ");
    char *pas = malloc(256);
    if(!fgets(pas, 256, tty)) exit(EXIT_FAILURE);
    pas[strcspn(pas, "\n")] = '\0';
    putchar('\n');

    p.c_lflag |= ECHO;
    if (tcsetattr(fileno(tty), TCSAFLUSH, &p)) exit(EXIT_FAILURE);

    if(fclose(tty) == EOF) exit(EXIT_FAILURE);
    uint32_t *key = passToKey(pas, strlen(pas));
    free(pas);

    return key;
}

void printHelp(FILE *f){
    fprintf(f,
        "Description:\n"
        "\tcc20 is a c implementation of the ChaCha20 "
        "algorithm. NOTE: this is not a secure or efficient "
        "implementation by any means and is "
        "only intended for educational purpose.\n\n"
        "Usage:\n"
        "\tcc20 <-e|d|h> [-i inputfile] [-o outputfile]\n\n"
        "Defaults:\n"
        "\t-i -\t\tRead input from stdin\n"
        "\t-o -\t\tPrint output to stdout\n"
        "Examples:\n"
        "\tcc20 -e -i plaintext -o ciphertext\n"
        "\tcc20 -d -i ciphertext -o plaintext\n\n"
    );
}

int main(int argc, char **argv){
    char ifile[128], ofile[128];
    strcpy(ifile, "-");
    strcpy(ofile, "-");


    #define ENCRYPT_FLAG 1
    #define DECRYPT_FLAG 2
    #define HELP_FLAG 4
    uint8_t flags = 0x00;

    char c;
    while ((c = getopt(argc, argv, ":hedi:o:")) != EOF){
        switch (c) {
            case 'h':
                printHelp(stdout);
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                if(strlen(optarg) < 128) strcpy(ifile, optarg);
                else {
                    fprintf(stderr,
                        "Argument for option -i exceeds 128 limit\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'o':
                if(strlen(optarg) < 128) strcpy(ofile, optarg);
                else {
                    fprintf(stderr,
                        "Argument for option -o exceeds 128 limit\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'e':
                flags |= ENCRYPT_FLAG;
                break;
            case 'd':
                flags |= DECRYPT_FLAG;
                break;
            case '?':
                fprintf(stderr, "Unknown option '-%c'\n", optopt);
                exit(EXIT_FAILURE);
                break;
            case ':':
                fprintf(stderr,
                    "Missing argument for option '-%c'\n", optopt);
                exit(EXIT_FAILURE);
                break;
        }
    }

    if(!(flags & ( ENCRYPT_FLAG | DECRYPT_FLAG))){
        fprintf(stderr,
            "Operation not specified.\n");
        printHelp(stderr);
        exit(EXIT_FAILURE);
    }

    if((flags & ENCRYPT_FLAG) && (flags & DECRYPT_FLAG)){
        fprintf(stderr,
            "-e and -d flag cannot be used at the same time.\n");
        exit(EXIT_FAILURE);
    }

    uint32_t *key = pass();

    if(flags & ENCRYPT_FLAG) encrypt(ifile, ofile, key);
    else decrypt(ifile, ofile, key);

    return EXIT_SUCCESS;
}
