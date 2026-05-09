#ifndef UTILS
#define UTILS


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_BYTES_IN_LINE 32
#define MAX_BYTES_IN_WORD 4


typedef enum TCError TCError;
enum TCError {
    NO_ERROR                  = 0x0000000000000000,
    BINARY_HASH_MISMATCH      = 0x0000000000000001,
    STRINGIFIED_HASH_MISMATCH = 0x0000000000000002,
};
#define NUM_ERROR_TYPES 2


typedef enum SHA_Algs SHA_Algs;
enum SHA_Algs {
    SHA224_ALG     = 0x0000000000000001,
    SHA256_ALG     = 0x0000000000000002,
    SHA384_ALG     = 0x0000000000000004,
    SHA512_ALG     = 0x0000000000000008,
    SHA512_224_ALG = 0x0000000000000010,
    SHA512_256_ALG = 0x0000000000000020,
};
#define NUM_ALGORITHMS 6
#define DEFAULT_ALGORITHMS_ARGVAL 0x000000000000003f


int hex_str_2_bin_str(char*, uint8_t*, size_t);
int bin_str_2_hex_str(uint8_t*, char*, size_t);
int hex_print(uint8_t*, size_t, size_t);
int compare_uint8_t_arrays(uint8_t*, uint8_t*, size_t);
int SHA_Algs_to_string(SHA_Algs, char*);


#endif