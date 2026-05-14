#include "SHA2Testing.h"


Testcase* Testcase_init(SHA_Algs input_algorithm){
    Testcase* tc;
    uint64_t hash_byte_size;

    // Allocate Testcase object
    tc = (Testcase*)calloc(1, sizeof(Testcase));
    if(tc == NULL){
        printf("ERROR: Could not allocate memory for Testcase object.\n");
        return NULL;
    }

    switch (input_algorithm){
    case SHA224_ALG:
        hash_byte_size = SHA224_HASH_BYTESIZE;
        tc->s224 = sha224_init();
        break;    
    case SHA256_ALG:
        hash_byte_size = SHA256_HASH_BYTESIZE;
        break;    
    case SHA384_ALG:
        hash_byte_size = SHA384_HASH_BYTESIZE;
        break;    
    case SHA512_ALG:
        hash_byte_size = SHA512_HASH_BYTESIZE;
        break;    
    case SHA512_224_ALG:
        hash_byte_size = SHA512_224_HASH_BYTESIZE;
        break;    
    case SHA512_256_ALG:
        hash_byte_size = SHA512_256_HASH_BYTESIZE;
        break;    
    default:
        printf("ERROR: The algorithm type provided is invalid: %lx.\n", (uint64_t)input_algorithm);
        return NULL;
    }

    // Set initial values
    tc->errors = NO_ERROR;
    tc->algorithm = input_algorithm;

    // Allocate buffers for hash values
    tc->bin_res_hash = (uint8_t*)calloc(hash_byte_size, sizeof(uint8_t));
    tc->str_res_hash = (char*)calloc((hash_byte_size * 2) + 1, sizeof(char));
    tc->bin_exp_hash = (uint8_t*)calloc(hash_byte_size, sizeof(uint8_t));
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
        break;    
    case SHA384_ALG:
        break;    
    case SHA512_ALG:
        break;    
    case SHA512_224_ALG:
        break;    
    case SHA512_256_ALG:
        break;    
    default:
        break;
    }

    // Deallocate buffers
    free(tc->bin_res_hash);
    free(tc->str_res_hash);
    free(tc->bin_exp_hash);
    if(tc->bin_msg != NULL){
        free(tc->bin_msg);
    }

    // Deallocate Testcase object
    free(tc);
}
