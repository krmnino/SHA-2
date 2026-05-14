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
    SHA_Algs algorithm;
    TCError errors;
};


Testcase* Testcase_init(SHA_Algs);
int Testcase_delete(Testcase*);


int sha224_tc();


#endif