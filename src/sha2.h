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


#ifndef SHA2H
#define SHA2H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define ROTR_U32(data, n_bits) \
        ((data << ((sizeof(uint32_t) * 8) - n_bits)) | (data >> n_bits))


#define SWAP_ENDIANESS_U32(data) \
        (((data & 0x000000ff) << 24) |  \
         ((data & 0x0000ff00) << 8 ) |  \
         ((data & 0x00ff0000) >> 8 ) |  \
         ((data & 0xff000000) >> 24))


static uint32_t SHA256_K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
#define N_SHA256_Ks \
        (sizeof(SHA256_K) / sizeof(uint32_t))


#define CALCULATE_SHA256_k(input_bitlen) \
        (SHA256_CHUNK_BITSIZE - ((input_bitlen + 1 + (sizeof(uint64_t) * 8)) % SHA256_CHUNK_BITSIZE))


/*===================================================================*/
/*                              SHA-224                              */
/*===================================================================*/
static uint32_t SHA224_INIT_HASH[] = {
    0xc1059ed8,
    0x367cd507,
    0x3070dd17,
    0xf70e5939,
    0xffc00b31,
    0x68581511,
    0x64f98fa7,
    0xbefa4fa4
};
#define SHA224_HASH_BYTESIZE_INTERNAL (sizeof(SHA224_INIT_HASH))
#define SHA224_HASH_BYTESIZE (SHA224_HASH_BYTESIZE_INTERNAL - 1)
#define SHA224_HASH_BITSIZE (SHA224_HASH_BYTESIZE_INTERNAL * 8)
#define SHA224_HASH_U32WORDS (SHA224_HASH_BYTESIZE_INTERNAL / sizeof(uint32_t))
#define SHA224_CHUNK_BITSIZE (SHA224_HASH_BITSIZE * 2)
#define SHA224_CHUNK_BYTESIZE (SHA224_CHUNK_BITSIZE / 8)


typedef struct sha224 sha224;
struct sha224{
    struct {
        union{
            uint32_t w0_63[N_SHA256_Ks];
            uint32_t w0_15[N_SHA256_Ks / 4];
            uint8_t buffer_u8[SHA224_CHUNK_BYTESIZE];
        };
    };
    uint32_t hash[SHA224_HASH_U32WORDS];
    uint64_t data_bytelen;
    bool big_endian;
    bool done;
    uint8_t buffer_idx;
};


sha224* sha224_init();
int sha224_chain(sha224*, uint8_t*, uint64_t);
int sha224_end(sha224*);
int sha224_delete(sha224*);
int sha224_stringify_hash(sha224*, char*);


/*===================================================================*/
/*                              SHA-256                              */
/*===================================================================*/
static uint32_t SHA256_INIT_HASH[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};
#define SHA256_HASH_BYTESIZE (sizeof(SHA256_INIT_HASH))
#define SHA256_HASH_BITSIZE (SHA256_HASH_BYTESIZE * 8)
#define SHA256_HASH_U32WORDS (SHA256_HASH_BYTESIZE / sizeof(uint32_t))
#define SHA256_CHUNK_BITSIZE (SHA256_HASH_BITSIZE * 2)
#define SHA256_CHUNK_BYTESIZE (SHA256_CHUNK_BITSIZE / 8)


typedef struct sha256 sha256;
struct sha256{
    struct {
        union{
            uint32_t w0_63[N_SHA256_Ks];
            uint32_t w0_15[N_SHA256_Ks / 4];
            uint8_t buffer_u8[SHA256_CHUNK_BYTESIZE];
        };
    };
    uint32_t hash[SHA256_HASH_U32WORDS];
    uint64_t data_bytelen;
    bool big_endian;
    bool done;
    uint8_t buffer_idx;
};


sha256* sha256_init();
int sha256_chain(sha256*, uint8_t*, uint64_t);
int sha256_end(sha256*);
int sha256_delete(sha256*);
int sha256_stringify_hash(sha256*, char*);


#endif