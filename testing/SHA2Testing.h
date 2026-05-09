#ifndef SHA2TESTING
#define SHA2TESTING

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "../res/ArgParsing_C.h"
#include "../res/Randomizer_C.h"
#include "../src/sha2.h"
#include "Utils.h"
#include "SHA224_TV.h"


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


typedef struct Context Context; 
struct Context{
    ArgParsing_C* ap;
    Randomizer_C* rnd;
    uint64_t algorithms;
    uint64_t n_tests;
    uint64_t testcase_counter;
    uint32_t seed;
    bool trace;
    bool infinite_loop;
};
extern Context ctxt;


typedef enum TCError TCError;
enum TCError {
    NO_ERROR                  = 0x0000000000000000,
    BINARY_HASH_MISMATCH      = 0x0000000000000001,
    STRINGIFIED_HASH_MISMATCH = 0x0000000000000002,
};


typedef struct Testcase Testcase;
struct Testcase{
    uint8_t* bin_msg;
    uint8_t* bin_res_hash;
    char* str_res_hash;
    uint8_t* bin_exp_hash;
    union{
        sha224* s224;
    };
    size_t tv_idx;
    size_t msg_bytelen;
    TCError errors;
};


int sha224_tc();

#endif