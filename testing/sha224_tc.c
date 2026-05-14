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


#include "SHA2Testing.h"


int sha224_tc(){
    Testcase* tc;
    TCError masked_error;
    uint64_t shifter;
    char print_buff[64];
    int ret;

    // Allocate and initialize Testcase object
    tc = Testcase_init(SHA224_ALG);
    if(tc == NULL){
        return -1;
    }

    // Pick a random index for the array of testcase vectors
    tc->tv_idx = Randomizer_C_gen_integral_range(ctxt.rnd, 0, (N_SHA224_TVS - 1));
    
    // Get the byte length of the test vector message
    tc->msg_bytelen = SHA224_TVS[tc->tv_idx].bitlen / 8;

    // Allocate buffers for the testcase
    tc->bin_msg = (uint8_t*)calloc(tc->msg_bytelen + 1, sizeof(uint8_t));

    // Convert test vector string fields to binary
    ret = hex_str_2_bin_str(SHA224_TVS[tc->tv_idx].msg, tc->bin_msg, tc->msg_bytelen * 2);
    if(ret != 0){
        return -1;
    }
    ret = hex_str_2_bin_str(SHA224_TVS[tc->tv_idx].hash, tc->bin_exp_hash, SHA224_HASH_BYTESIZE * 2);
    if(ret != 0){
        return -1;
    }

    // Perform the hashing operation
    sha224_chain(tc->s224, tc->bin_msg, tc->msg_bytelen);
    sha224_end(tc->s224);
    sha224_get_hash(tc->s224, tc->bin_res_hash);
    sha224_get_stringified_hash(tc->s224, tc->str_res_hash);
    
    // Validate results
    if(compare_uint8_t_arrays(tc->bin_res_hash, tc->bin_exp_hash, SHA224_HASH_BYTESIZE) != 0){
        tc->errors = tc->errors | BINARY_HASH_MISMATCH;
    }
    if(strcmp(tc->str_res_hash, SHA224_TVS[tc->tv_idx].hash) != 0){
        tc->errors = tc->errors | STRINGIFIED_HASH_MISMATCH;
    }

    // Print error report
    if(tc->errors != NO_ERROR | ctxt.trace){
        printf("--------------------- START TESTCASE REPORT ---------------------\n");
        memset((void*)&print_buff, 0, sizeof(print_buff));
        SHA_Algs_to_string(tc->algorithm, (char*)&print_buff);
        printf("Testcase #%ld\n", ctxt.testcase_counter);
        printf("Seed : 0x%x\n", Randomizer_C_get_root_seed(ctxt.rnd));
        printf("Algorithm : %s\n", print_buff);
        printf("Errors:\n");
        if(tc->errors == NO_ERROR){
            TCError_to_string(tc->errors, (char*)&print_buff);
            printf(" - %s\n", print_buff);
        }
        else{
            shifter = 0x1;
            for(size_t i = 0; i < NUM_ERROR_TYPES; i++){
                masked_error = tc->errors & shifter;
                if(masked_error != NO_ERROR){
                    TCError_to_string(masked_error, (char*)&print_buff);
                    printf(" - %s\n", print_buff);
                }
                shifter = shifter << 1;
            }
        }
        printf("Message size : %ld bytes\n", tc->msg_bytelen);
        printf(">>> Message start\n");
        ret = hex_print(tc->bin_msg, tc->msg_bytelen, 0x0);
        if(ret != 0){
            return -1;
        }
        printf("<<< Message end\n");
        printf("Resulting hash : %s\n", tc->str_res_hash);
        printf("Expected hash  : %s\n", SHA224_TVS[tc->tv_idx].hash);
        printf("---------------------- END TESTCASE REPORT ----------------------\n");

        // Deallocate Testcase object
        ret = Testcase_delete(tc);
        if(ret != 0){
            return -1;
        }
    }

    return 0;
}