#ifndef CONTEXT
#define CONTEXT

#include <stdint.h>
#include <string.h>
#include "../res/ArgParsing_C.h"
#include "../res/Randomizer_C.h"
#include "../src/sha2.h"


//#define SHA224_ARG     0x0000000000000001
//#define SHA256_ARG     0x0000000000000002
//#define SHA384_ARG     0x0000000000000004
//#define SHA512_ARG     0x0000000000000008
//#define SHA512_224_ARG 0x0000000000000010
//#define SHA512_256_ARG 0x0000000000000020

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

static struct Context{
    ArgParsing_C* ap;
    Randomizer_C* rnd;
    uint64_t algorithms;
    uint64_t n_tests;
    uint32_t seed;
    bool trace;
} Context;


#endif