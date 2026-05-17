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


#define _GNU_SOURCE


typedef struct Testcase Testcase;
struct Testcase{
    uint8_t* bin_msg;
    uint8_t* bin_res_hash;
    uint8_t* bin_exp_hash;
    char* str_res_hash;
    TestVector* tv_array;
    uint32_t* sub_bin_msg_sizes;
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
    size_t sub_bin_msg_idx;
    SHA_Algs algorithm;
    TCError errors;
    uint32_t seed;
};


typedef struct Context Context; 
struct Context{
    ArgParsing_C* ap;
    Randomizer_C* rnd;
    Testcase* error_tcs_head;
    Testcase* error_tcs_curr;
    Testcase* tc;
    size_t max_errors;
    size_t error_counter;
    size_t max_testcases;
    size_t testcase_counter;
    uint64_t algorithms;
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