/*
MIT License

Copyright (c) 2026 Kurt Manrique-Nino

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


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
    NO_ERROR                       = 0x0000000000000000,
    BINARY_HASH_MISMATCH           = 0x0000000000000001,
    STRINGIFIED_HASH_MISMATCH      = 0x0000000000000002,
    SHA2_CHAIN_FAIL                = 0x0000000000000004,
    SHA2_END_FAIL                  = 0x0000000000000008,
    SHA2_GET_HASH_FAIL             = 0x0000000000000010,
    SHA2_GET_STRINGIFIED_HASH_FAIL = 0x0000000000000020,
    SHA2_INIT_FAIL                 = 0x0000000000000040,
    SHA2_DELETE_FAIL               = 0x0000000000000080,
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
int TCError_to_string(TCError, char*);


#endif