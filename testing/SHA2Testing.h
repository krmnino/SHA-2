#ifndef SHA2TESTING
#define SHA2TESTING

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include "../res/ArgParsing_C.h"
#include "../res/Randomizer_C.h"
#include "../src/sha2.h"
#include "Utils.h"
#include "TestVector.h"
#include "SHA224_TV.h"
#include "SHA256_TV.h"
#include "SHA384_TV.h"
#include "SHA512_TV.h"
#include "SHA512_224_TV.h"
#include "SHA512_256_TV.h"


#define _GNU_SOURCE


typedef struct Testcase Testcase;
struct Testcase{
    uint8_t* bin_msg;
    uint8_t* bin_res_hash;
    uint8_t* bin_exp_hash;
    char* str_res_hash;
    TestVector* tv_array;
    Testcase* next;
    union{
        sha224* s224;
        sha256* s256;
        sha384* s384;
        sha512* s512;
        sha512_224* s512_224;
        sha512_256* s512_256;
    };
    size_t tv_idx;
    size_t n_tvs;
    size_t msg_bytelen;
    size_t hash_bytelen;
    SHA_Algs algorithm;
    TCError errors;
    uint32_t seed;
};


typedef struct Context Context; 
struct Context{
    ArgParsing_C* ap;
    Randomizer_C* rnd;
    Testcase* error_tcs;
    Testcase* tc;
    uint64_t algorithms;
    uint64_t n_tests;
    uint64_t testcase_counter;
    uint32_t init_seed;
    bool trace;
    bool infinite_loop;
};
extern Context ctxt;


Testcase* Testcase_init(SHA_Algs);
int Testcase_delete(Testcase*);
int Testcase_validate(Testcase*);
int Testcase_report(Testcase*);


int sha224_tc();


#endif