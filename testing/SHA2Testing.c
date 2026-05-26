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
#include "SHA224_TV.h"
#include "SHA256_TV.h"
#include "SHA384_TV.h"
#include "SHA512_TV.h"
#include "SHA512_224_TV.h"
#include "SHA512_256_TV.h"


Testcase* Testcase_init(SHA_Algs input_algorithm){
    Testcase* tc;
    int ret;

    // Allocate Testcase object
    tc = (Testcase*)calloc(1, sizeof(Testcase));
    if(tc == NULL){
        printf("ERROR: Could not allocate memory for Testcase object.\n");
        return NULL;
    }

    // Initialize algorithm specific fields
    switch (input_algorithm){
    case SHA224_ALG:
        tc->hash_bytelen = SHA224_HASH_BYTESIZE;
        tc->tv_array = SHA224_TVS;
        tc->n_tvs = sizeof(SHA224_TVS) / sizeof(SHA224_TVS[0]);
        break;    
    case SHA256_ALG:
        tc->hash_bytelen = SHA256_HASH_BYTESIZE;
        tc->tv_array = SHA256_TVS;
        tc->n_tvs = sizeof(SHA256_TVS) / sizeof(SHA256_TVS[0]);
        break;    
    case SHA384_ALG:
        tc->hash_bytelen = SHA384_HASH_BYTESIZE;
        tc->tv_array = SHA384_TVS;
        tc->n_tvs = sizeof(SHA384_TVS) / sizeof(SHA384_TVS[0]);
        break;    
    case SHA512_ALG:
        tc->hash_bytelen = SHA512_HASH_BYTESIZE;
        tc->tv_array = SHA512_TVS;
        tc->n_tvs = sizeof(SHA512_TVS) / sizeof(SHA512_TVS[0]);
        break;    
    case SHA512_224_ALG:
        tc->hash_bytelen = SHA512_224_HASH_BYTESIZE;
        tc->tv_array = SHA512_224_TVS;
        tc->n_tvs = sizeof(SHA512_224_TVS) / sizeof(SHA512_224_TVS[0]);
        break;    
    case SHA512_256_ALG:
        tc->hash_bytelen = SHA512_256_HASH_BYTESIZE;
        tc->tv_array = SHA512_256_TVS;
        tc->n_tvs = sizeof(SHA512_256_TVS) / sizeof(SHA512_256_TVS[0]);
        break;    
    default:
        printf("ERROR: The algorithm type provided is invalid: %lx.\n", (uint64_t)input_algorithm);
        return NULL;
    }

    // Set initial values
    tc->seed = Randomizer_C_get_root_seed(ctxt.rnd);
    tc->errors = NO_ERROR;
    tc->algorithm = input_algorithm;

    // Pick a random index for the array of testcase vectors
    tc->tv_idx = Randomizer_C_gen_integral_range(ctxt.rnd, 0, (tc->n_tvs - 1));
    
    // Get the byte length of the test vector message
    tc->msg_bytelen = tc->tv_array[tc->tv_idx].bitlen / 8;

    // Allocate buffers for hash values
    tc->bin_msg = (uint8_t*)calloc(tc->msg_bytelen + 1, sizeof(uint8_t));
    tc->bin_res_hash = (uint8_t*)calloc(tc->hash_bytelen, sizeof(uint8_t));
    tc->str_res_hash = (char*)calloc((tc->hash_bytelen * 2) + 1, sizeof(char));
    tc->bin_exp_hash = (uint8_t*)calloc(tc->hash_bytelen, sizeof(uint8_t));

    // Convert test vector string fields to binary
    ret = hex_str_2_bin_str(tc->tv_array[tc->tv_idx].msg, tc->bin_msg, tc->msg_bytelen * 2);
    if(ret != 0){
        return NULL;
    }
    ret = hex_str_2_bin_str(tc->tv_array[tc->tv_idx].hash, tc->bin_exp_hash, tc->hash_bytelen * 2);
    if(ret != 0){
        return NULL;
    }
    return tc;
}


int Testcase_delete(Testcase* tc){
    // Validate input
    if(tc == NULL){
        printf("ERROR: Pointer to Testcase instance is NULL.\n");
        return -1;
    }

    // Deallocate buffers
    free(tc->bin_res_hash);
    free(tc->str_res_hash);
    free(tc->bin_exp_hash);
    free(tc->bin_msg);
    if(tc->sub_bin_msg_sizes != NULL){
        free(tc->sub_bin_msg_sizes);
    }
    
    // Deallocate Testcase object
    free(tc);
    return 0;
}


int Testcase_validate(Testcase* tc){
    // Validate input
    if(tc == NULL){
        printf("ERROR: Pointer to Testcase instance is NULL.\n");
        return -1;
    }

    // Validate results
    if(compare_uint8_t_arrays(tc->bin_res_hash, tc->bin_exp_hash, tc->hash_bytelen) != 0){
        tc->errors = tc->errors | BINARY_HASH_MISMATCH;
    }
    if(strcmp(tc->str_res_hash, tc->tv_array[tc->tv_idx].hash) != 0){
        tc->errors = tc->errors | STRINGIFIED_HASH_MISMATCH;
    }
    return 0;
}


int Testcase_report(Testcase* tc){
    char print_buff[64];
    uint8_t* curr_bin_msg;
    uint64_t shifter;
    size_t offset;
    TCError masked_error;
    int ret;

    // Validate input
    if(tc == NULL){
        printf("ERROR: Pointer to Testcase instance is NULL.\n");
        return -1;
    }

    // Print testcase report
    printf("--------------------- START TESTCASE REPORT ---------------------\n");
    memset((void*)&print_buff, 0, sizeof(print_buff));
    SHA_Algs_to_string(tc->algorithm, (char*)&print_buff);
    printf("Testcase #%ld\n", ctxt.testcase_counter);
    printf("Seed : 0x%x\n", tc->seed);
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
    printf(">>> Full message start\n");
    ret = hex_print(tc->bin_msg, tc->msg_bytelen, 0x0);
    if(ret != 0){
        return -1;
    }
    printf("<<< Full message end\n");
    if(tc->msg_bytelen != 0){
        printf(">>> Message sections start\n");
        curr_bin_msg = ctxt.tc->bin_msg;
        offset = 0;
        for(size_t i = 0; i < ctxt.tc->sub_bin_msg_idx; i++){
            printf("Section byte size: %d bytes\n", ctxt.tc->sub_bin_msg_sizes[i]);
            hex_print(curr_bin_msg, ctxt.tc->sub_bin_msg_sizes[i], offset);
            curr_bin_msg += ctxt.tc->sub_bin_msg_sizes[i];
            offset += ctxt.tc->sub_bin_msg_sizes[i];
        }
        printf("<<< Message sections end\n");
    }
    printf("Resulting hash : %s\n", tc->str_res_hash);
    printf("Expected hash  : %s\n", tc->tv_array[tc->tv_idx].hash);
    printf("---------------------- END TESTCASE REPORT ----------------------\n");
    return 0;
}