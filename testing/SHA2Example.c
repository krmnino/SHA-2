#include "../src/sha2.h"
 

int sha224_test(){
    sha224* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-224.";

    s = sha224_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha224_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha224_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA224_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha224_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA224_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha224_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha224_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-224\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA224_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-224\n");
    return 0;
}


int sha256_test(){
    sha256* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-256.";

    s = sha256_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha256_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha256_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA256_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha256_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA256_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha256_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha256_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-256\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA256_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-256\n");
    return 0;
}


int sha384_test(){
    sha384* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-384.";

    s = sha384_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha384_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha384_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA384_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha384_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA384_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha384_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha384_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-384\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA384_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-384\n");
    return 0;
}


int sha512_test(){
    sha512* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-512.";

    s = sha512_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha512_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha512_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA512_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha512_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha512_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha512_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-512\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-512\n");
    return 0;
}


int sha512_224_test(){
    sha512_224* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-512/224.";

    s = sha512_224_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha512_224_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha512_224_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA512_224_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha512_224_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha512_224_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha512_224_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-512/224\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-512/224\n");
    return 0;
}


int sha512_256_test(){
    sha512_256* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    int ret;
    
    input_message = "This is hashed with SHA-512/256.";

    s = sha512_256_init();
    if(s == NULL){
        return -1;
    }
    
    ret = sha512_256_chain(s, (uint8_t*)input_message, strlen(input_message));
    if(s == NULL){
        return -1;
    }

    ret = sha512_256_end(s);
    if(s == NULL){
        return -1;
    }
    
    str_output_hash = (char*)calloc(((SHA512_256_HASH_BYTESIZE * 2)) + 1, sizeof(char));
    ret = sha512_256_get_stringified_hash(s, str_output_hash);
    if(ret != 0){
        return -1;
    }
    
    hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
    ret = sha512_256_get_hash(s, hex_output_hash);
    if(ret != 0){
        return -1;
    }
    
    ret = sha512_256_delete(s);
    if(ret != 0){
        return -1;
    }

    printf(">>> SHA-512/256\n");
    printf("Input message      : %s\n", input_message);
    printf("Output hex hash    : ");
    for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
        printf("%02x", hex_output_hash[i]);
    }
    printf("\n");
    printf("Output string hash : %s\n", str_output_hash);
    free(str_output_hash);
    free(hex_output_hash);
    printf("<<< SHA-512/256\n");
    return 0;
}


int main(int argc, char* argv[]){
    sha224_test();
    sha256_test();
    sha384_test();
    sha512_test();
    sha512_224_test();
    sha512_256_test();
    return 0;
}