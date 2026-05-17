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
        tc->s224 = sha224_init();
        break;    
    case SHA256_ALG:
        tc->hash_bytelen = SHA256_HASH_BYTESIZE;
        tc->tv_array = SHA256_TVS;
        tc->n_tvs = sizeof(SHA256_TVS) / sizeof(SHA256_TVS[0]);
        tc->s256 = sha256_init();
        break;    
    case SHA384_ALG:
        tc->hash_bytelen = SHA384_HASH_BYTESIZE;
        break;    
    case SHA512_ALG:
        tc->hash_bytelen = SHA512_HASH_BYTESIZE;
        break;    
    case SHA512_224_ALG:
        tc->hash_bytelen = SHA512_224_HASH_BYTESIZE;
        break;    
    case SHA512_256_ALG:
        tc->hash_bytelen = SHA512_256_HASH_BYTESIZE;
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
    ret = hex_str_2_bin_str(SHA224_TVS[tc->tv_idx].msg, tc->bin_msg, tc->msg_bytelen * 2);
    if(ret != 0){
        return NULL;
    }
    ret = hex_str_2_bin_str(SHA224_TVS[tc->tv_idx].hash, tc->bin_exp_hash, SHA224_HASH_BYTESIZE * 2);
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

    // Deallocate SHA2 object
    switch (tc->algorithm){
    case SHA224_ALG:
        sha224_delete(tc->s224);
        break;    
    case SHA256_ALG:
        sha256_delete(tc->s256);
        break;    
    case SHA384_ALG:
        sha384_delete(tc->s384);
        break;    
    case SHA512_ALG:
        sha512_delete(tc->s512);
        break;    
    case SHA512_224_ALG:
        sha512_224_delete(tc->s512_224);
        break;    
    case SHA512_256_ALG:
        sha512_256_delete(tc->s512_256);
        break;    
    default:
        break;
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
    if(strcmp(tc->str_res_hash, SHA224_TVS[tc->tv_idx].hash) != 0){
        tc->errors = tc->errors | STRINGIFIED_HASH_MISMATCH;
    }
    return 0;
}


int Testcase_report(Testcase* tc){
    char print_buff[64];
    uint64_t shifter;
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
    printf(">>> Message start\n");
    ret = hex_print(tc->bin_msg, tc->msg_bytelen, 0x0);
    if(ret != 0){
        return -1;
    }
    printf("<<< Message end\n");
    if(tc->msg_bytelen != 0){
        printf(">>> Message sections start\n");
        printf("<<< Message sections end\n");
    }
    printf("Resulting hash : %s\n", tc->str_res_hash);
    printf("Expected hash  : %s\n", tc->tv_array[tc->tv_idx].hash);
    printf("---------------------- END TESTCASE REPORT ----------------------\n");
    return 0;
}