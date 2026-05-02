#ifndef CONTEXT
#define CONTEXT

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "../res/ArgParsing_C.h"
#include "../res/Randomizer_C.h"
#include "../src/sha2.h"


#define _GNU_SOURCE


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


static struct Context{
    ArgParsing_C* ap;
    Randomizer_C* rnd;
    uint64_t algorithms;
    uint64_t n_tests;
    uint64_t testcase_counter;
    uint32_t seed;
    bool trace;
    bool infinite_loop;
} Context;


#endif