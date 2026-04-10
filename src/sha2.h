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


static const int ENDIAN = 1;
#define IS_LITTLE_ENDIAN() ((*(uint8_t*)&ENDIAN) == 0x01)


#define ROTR_U32(data, n_bits) \
        ((data << ((sizeof(uint32_t) * 8) - n_bits)) | (data >> n_bits))


#define ROTR_U64(data, n_bits) \
        ((data << ((sizeof(uint64_t) * 8) - n_bits)) | (data >> n_bits))


#define SWAP_ENDIANESS_U32(data) \
        (((data & 0x000000ff) << 24) |  \
         ((data & 0x0000ff00) << 8 ) |  \
         ((data & 0x00ff0000) >> 8 ) |  \
         ((data & 0xff000000) >> 24))


#define SWAP_ENDIANESS_U64(data) \
        (((data & 0x00000000000000ff) << 56) |  \
         ((data & 0x000000000000ff00) << 40) |  \
         ((data & 0x0000000000ff0000) << 24) |  \
         ((data & 0x00000000ff000000) << 8 ) |  \
         ((data & 0x000000ff00000000) >> 8 ) |  \
         ((data & 0x0000ff0000000000) >> 24) |  \
         ((data & 0x00ff000000000000) >> 40) |  \
         ((data & 0xff00000000000000) >> 56))


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


static uint64_t SHA512_K[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};
#define N_SHA512_Ks \
        (sizeof(SHA512_K) / sizeof(uint64_t))


#define CALCULATE_SHA256_k(input_bitlen) \
        (SHA256_CHUNK_BITSIZE - ((input_bitlen + 1 + (sizeof(uint64_t) * 8)) % SHA256_CHUNK_BITSIZE))

        
#define CALCULATE_SHA512_k(input_bitlen) \
        (SHA512_CHUNK_BITSIZE - ((input_bitlen + 1 + (sizeof(__uint128_t) * 8)) % SHA512_CHUNK_BITSIZE))


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
#define SHA224_HASH_BYTESIZE (SHA224_HASH_BYTESIZE_INTERNAL - sizeof(uint32_t))
#define SHA224_HASH_BITSIZE (SHA224_HASH_BYTESIZE_INTERNAL * 8)
#define SHA224_HASH_U32WORDS (SHA224_HASH_BYTESIZE_INTERNAL / sizeof(uint32_t))
#define SHA224_CHUNK_BITSIZE (SHA224_HASH_BITSIZE * 2)
#define SHA224_CHUNK_BYTESIZE (SHA224_CHUNK_BITSIZE / 8)


typedef struct sha224 sha224;
struct sha224{
    union{
        uint32_t w0_63[N_SHA256_Ks];
        uint32_t w0_15[N_SHA256_Ks / 4];
        uint8_t buffer_u8[SHA224_CHUNK_BYTESIZE];
    };
    uint32_t hash[SHA224_HASH_U32WORDS];
    uint64_t data_bytelen;
    bool done;
    uint8_t buffer_idx;
};


sha224* sha224_init();
int sha224_chain(sha224*, uint8_t*, uint64_t);
int sha224_end(sha224*);
int sha224_delete(sha224*);
int sha224_get_hash(sha224*, uint8_t*);
int sha224_get_stringified_hash(sha224*, char*);


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
    union{
        uint32_t w0_63[N_SHA256_Ks];
        uint32_t w0_15[N_SHA256_Ks / 4];
        uint8_t buffer_u8[SHA256_CHUNK_BYTESIZE];
    };
    uint32_t hash[SHA256_HASH_U32WORDS];
    uint64_t data_bytelen;
    bool done;
    uint8_t buffer_idx;
};


sha256* sha256_init();
int sha256_chain(sha256*, uint8_t*, uint64_t);
int sha256_end(sha256*);
int sha256_delete(sha256*);
int sha256_get_stringified_hash(sha256*, char*);


/*===================================================================*/
/*                              SHA-384                              */
/*===================================================================*/
static uint64_t SHA384_INIT_HASH[] = {
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939, 
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
};
#define SHA384_HASH_BYTESIZE_INTERNAL (sizeof(SHA384_INIT_HASH))
#define SHA384_HASH_BYTESIZE (SHA384_HASH_BYTESIZE_INTERNAL - (sizeof(uint64_t) * 2))
#define SHA384_HASH_BITSIZE (SHA384_HASH_BYTESIZE_INTERNAL * 8)
#define SHA384_HASH_U64WORDS (SHA384_HASH_BYTESIZE_INTERNAL / sizeof(uint64_t))
#define SHA384_CHUNK_BITSIZE (SHA384_HASH_BITSIZE * 2)
#define SHA384_CHUNK_BYTESIZE (SHA384_CHUNK_BITSIZE / 8)


typedef struct sha384 sha384;
struct sha384{
    union{
        uint64_t w0_80[N_SHA512_Ks];
        uint64_t w0_15[N_SHA512_Ks / 4];
        uint8_t buffer_u8[SHA384_CHUNK_BYTESIZE];
    };
    uint64_t hash[SHA384_HASH_U64WORDS];
    __uint128_t data_bytelen;
    bool done;
    uint8_t buffer_idx;
};


sha384* sha384_init();
int sha384_chain(sha384*, uint8_t*, uint64_t);
int sha384_end(sha384*);
int sha384_delete(sha384*);
int sha384_get_stringified_hash(sha384*, char*);


/*===================================================================*/
/*                              SHA-512                              */
/*===================================================================*/
static uint64_t SHA512_INIT_HASH[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};
#define SHA512_HASH_BYTESIZE (sizeof(SHA512_INIT_HASH))
#define SHA512_HASH_BITSIZE (SHA512_HASH_BYTESIZE * 8)
#define SHA512_HASH_U64WORDS (SHA512_HASH_BYTESIZE / sizeof(uint64_t))
#define SHA512_CHUNK_BITSIZE (SHA512_HASH_BITSIZE * 2)
#define SHA512_CHUNK_BYTESIZE (SHA512_CHUNK_BITSIZE / 8)


typedef struct sha512 sha512;
struct sha512{
    union{
        uint64_t w0_80[N_SHA512_Ks];
        uint64_t w0_15[N_SHA512_Ks / 4];
        uint8_t buffer_u8[SHA512_CHUNK_BYTESIZE];
    };
    uint64_t hash[SHA512_HASH_U64WORDS];
    __uint128_t data_bytelen;
    bool done;
    uint8_t buffer_idx;
};


sha512* sha512_init();
int sha512_chain(sha512*, uint8_t*, uint64_t);
int sha512_end(sha512*);
int sha512_delete(sha512*);
int sha512_get_stringified_hash(sha512*, char*);


#endif