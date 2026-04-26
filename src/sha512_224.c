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


#include "sha2.h"


sha512_224* sha512_224_init(){
    sha512_224* s;

    // Allocate sha512_224 instance
    s = (sha512_224*)calloc(1, sizeof(sha512_224));
    if(s == NULL){
        printf("ERROR: Could not allocate memory for sha512_224 instance.\n");
        return NULL;
    }

    // Initialize hash array
    memcpy((void*)s->hash, (void*)SHA512_224_INIT_HASH, SHA512_224_HASH_BYTESIZE_INTERNAL);
    return s;
}


int sha512_224_process(sha512_224* s){
    union{
        uint64_t letters[SHA512_224_HASH_U64WORDS];
        struct{
            uint64_t a;
            uint64_t b;
            uint64_t c;
            uint64_t d;
            uint64_t e;
            uint64_t f;
            uint64_t g;
            uint64_t h;
        };
    } loc;
    uint64_t s0;
    uint64_t s1;
    uint64_t ss0;
    uint64_t ss1;
    uint64_t ch;
    uint64_t maj;
    uint64_t temp1;
    uint64_t temp2;

    // Validate input
    if(s == NULL){
        printf("ERROR: Could not allocate memory for sha512_224 instance.\n");
        return -1;
    }

    // If in little-endian system, we need to convert the word to big-endian form
    if(IS_LITTLE_ENDIAN()){
        for(size_t i = 0; i < (N_SHA512_Ks / 4); i++){
            s->w0_15[i] = SWAP_ENDIANESS_U64(s->w0_15[i]);
        }
    }

    // Extend first 16 words to the remaining 64 words
    for(size_t i = 16; i < N_SHA512_Ks; i++){
        s0 = ROTR_U64(s->w0_80[i - 15], 1) ^ ROTR_U64(s->w0_80[i - 15], 8) ^ (s->w0_80[i - 15] >> 7);
        s1 = ROTR_U64(s->w0_80[i - 2], 19) ^ ROTR_U64(s->w0_80[i - 2], 61) ^ (s->w0_80[i - 2] >> 6);
        s->w0_80[i] = s->w0_80[i - 16] + s0 + s->w0_80[i - 7] + s1;
    }
    // Copy current hash value into letters array
    memcpy((void*)loc.letters, (void*)s->hash, SHA512_224_HASH_BYTESIZE_INTERNAL);
    
    // Compression function
    for(size_t i = 0; i < N_SHA512_Ks; i++){
        ss1 = ROTR_U64(loc.e, 14) ^ ROTR_U64(loc.e, 18) ^ ROTR_U64(loc.e, 41);
        ch = (loc.e & loc.f) ^ ((~loc.e) & loc.g);
        temp1 = loc.h + ss1 + ch + SHA512_K[i] + s->w0_80[i];
        ss0 = ROTR_U64(loc.a, 28) ^ ROTR_U64(loc.a, 34) ^ ROTR_U64(loc.a, 39);
        maj = (loc.a & loc.b) ^ (loc.a & loc.c) ^ (loc.b & loc.c);
        temp2 = ss0 + maj;
        loc.h = loc.g;
        loc.g = loc.f;
        loc.f = loc.e;
        loc.e = loc.d + temp1;
        loc.d = loc.c;
        loc.c = loc.b;
        loc.b = loc.a;
        loc.a = temp1 + temp2;
    }
    // Add the compressed chunk to the current hash value
    for(size_t i = 0; i < SHA512_224_HASH_U64WORDS; i++){
        s->hash[i] += loc.letters[i];
    }
    return 0;
}


int sha512_224_chain(sha512_224* s, uint8_t* input_data, uint64_t input_bytelen){
    uint32_t bytes_to_move;
    uint8_t* curr_input_data;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha512_224 instance is NULL.\n");
        return -1;
    }
    if(input_data == NULL){
        printf("ERROR: Pointer to input data is NULL.\n");
        return -1;
    }

    // Process input data in 128-byte (1024-bit) chunks 
    curr_input_data = input_data;
    while(true){
        if(s->buffer_idx == SHA512_224_CHUNK_BYTESIZE){
            sha512_224_process(s);
            memset(s->buffer_u8, 0, SHA512_224_CHUNK_BYTESIZE);
            s->buffer_idx = 0;
            continue;
        }
        if(input_bytelen == 0){
            break;
        }
        bytes_to_move = SHA512_224_CHUNK_BYTESIZE - s->buffer_idx;
        if(bytes_to_move > input_bytelen){
            bytes_to_move = input_bytelen;
        }
        memcpy((void*)(s->buffer_u8 + s->buffer_idx), (void*)curr_input_data, bytes_to_move);
        curr_input_data += bytes_to_move; 
        s->buffer_idx += bytes_to_move;
        s->data_bytelen += bytes_to_move;
        input_bytelen -= bytes_to_move;
    }
    return 0;
}


int sha512_224_end(sha512_224* s){
    uint32_t k;
    union{
        __uint128_t integer;
        uint8_t array[sizeof(__uint128_t)];
    } be_u128_src;
    union{
        __uint128_t integer;
        uint8_t array[sizeof(__uint128_t)];
    } be_u128_dest;
    
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha512_224 instance is NULL.\n");
        return -1;
    }
    if(s->done){
        printf("ERROR: Hash processing is already complete.\n");
        return -1;    
    }

    // Calculate k value such that:
    // (L * 8) + 1 + k + 128) mod 1024
    // where L = data length in bytes
    s->buffer_u8[s->buffer_idx++] = 0x80;
    if((s->data_bytelen % 128) < (SHA512_224_CHUNK_BYTESIZE - sizeof(__uint128_t))){
        // There is room in the current chunk for padding and length
        k = (CALCULATE_SHA512_k(s->data_bytelen * 8) + 1) / 8;
        for(uint8_t i = s->buffer_idx; i < (s->buffer_idx + k); i++){
            s->buffer_u8[i] = 0x00;
        }
        s->buffer_idx += (k - 1);
    }
    else{
        // Not enough room, add some padding and process the current chunk,
        // Then, add padding and the bit length to the next one
        for(uint8_t i = s->buffer_idx; i < SHA512_224_CHUNK_BYTESIZE; i++){
            s->buffer_u8[i] = 0x00;
        }
        sha512_224_process(s);
        memset((void*)s->buffer_u8, 0, SHA512_224_CHUNK_BYTESIZE);
        s->buffer_idx = SHA512_224_CHUNK_BYTESIZE - sizeof(__uint128_t);
    }

    // Append data length in big endian form
    be_u128_src.integer = s->data_bytelen * 8;
    if(IS_LITTLE_ENDIAN()){
        for(size_t i = 0; i < sizeof(__uint128_t); i++){
            be_u128_dest.array[i] = be_u128_src.array[sizeof(__uint128_t) - i - 1];
        }
    }
    else{
        be_u128_dest.integer = be_u128_src.integer;
    }
    for(size_t i = 0; i < sizeof(__uint128_t); i++){
        s->buffer_u8[s->buffer_idx++] = be_u128_dest.array[i];
    }

    // Process the last chunk
    sha512_224_process(s);

    // If in a litte endian system, convert final hash to big endian form
    if(IS_LITTLE_ENDIAN()){
        for(size_t i = 0; i < SHA512_224_HASH_U64WORDS; i++){
            s->hash[i] = SWAP_ENDIANESS_U64(s->hash[i]);
        }
        s->done = true;
    }
    return 0;
}


int sha512_224_delete(sha512_224* s){
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha512_224 instance is NULL.\n");
        return -1;
    }

    free(s);
    return 0;
}


int sha512_224_get_hash(sha512_224* s, uint8_t* out_buffer){
    uint8_t* curr_hash_ptr;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha512_224 instance is NULL.\n");
        return -1;
    }
    if(!s->done){
        printf("ERROR: Hash processing is not complete.\n");
        return -1;
    }
    if(out_buffer == NULL){
        printf("ERROR: Pointer to output buffer is NULL.\n");
        return -1;    
    }
    
    curr_hash_ptr = (uint8_t*)s->hash;
    for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
        out_buffer[i] = curr_hash_ptr[i];
    }
    return 0;
}


int sha512_224_get_stringified_hash(sha512_224* s, char* out_buffer){
    union{
        uint64_t integer;
        uint8_t array[sizeof(uint64_t)];
    } u64_buff;
    size_t out_buffer_idx;
    bool done;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha512_224 instance is NULL.\n");
        return -1;
    }
    if(!s->done){
        printf("ERROR: Hash processing is not complete.\n");
        return -1;
    }
    if(out_buffer == NULL){
        printf("ERROR: Pointer to output buffer is NULL.\n");
        return -1;    
    }    

    out_buffer_idx = 0;
    done = false;
    for(size_t i = 0; i < SHA512_224_HASH_U64WORDS && !done; i++){
        u64_buff.integer = s->hash[i];
        for(size_t j = 0; j < sizeof(uint64_t) && !done; j++){
            sprintf((char*)&out_buffer[out_buffer_idx], "%02x", u64_buff.array[j]);
            out_buffer_idx += 2;
            if((out_buffer_idx / 2) >= SHA512_224_HASH_BYTESIZE){
                done = true;
            }
        }
    }
    return 0;
}
