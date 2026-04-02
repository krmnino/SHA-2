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


sha224* sha224_init(){
    sha224* s;

    // Allocate sha224 instance
    s = (sha224*)calloc(1, sizeof(sha224));
    if(s == NULL){
        printf("ERROR: Could not allocate memory for sha224 instance.\n");
        return NULL;
    }

    // Initialize hash array
    memcpy((void*)s->hash, (void*)SHA224_INIT_HASH, SHA224_HASH_BYTESIZE_INTERNAL);    
    return s;
}


int sha224_process(sha224* s){
    union{
        uint32_t letters[SHA224_HASH_U32WORDS];
        struct{
            uint32_t a;
            uint32_t b;
            uint32_t c;
            uint32_t d;
            uint32_t e;
            uint32_t f;
            uint32_t g;
            uint32_t h;
        };
    } loc;
    uint32_t s0;
    uint32_t s1;
    uint32_t ss0;
    uint32_t ss1;
    uint32_t ch;
    uint32_t maj;
    uint32_t temp1;
    uint32_t temp2;

    // Validate input
    if(s == NULL){
        printf("ERROR: Could not allocate memory for sha224 instance.\n");
        return -1;
    }

    // If in little-endian system, we need to convert the word to big-endian form
    if(IS_LITTLE_ENDIAN()){
        for(size_t i = 0; i < (N_SHA256_Ks / 4); i++){
            s->w0_15[i] = SWAP_ENDIANESS_U32(s->w0_15[i]);
        }
    }

    // Extend first 16 words to the remaining 48 words
    for(size_t i = 16; i < N_SHA256_Ks; i++){
        s0 = ROTR_U32(s->w0_63[i - 15], 7) ^ ROTR_U32(s->w0_63[i - 15], 18) ^ (s->w0_63[i - 15] >> 3);
        s1 = ROTR_U32(s->w0_63[i - 2], 17) ^ ROTR_U32(s->w0_63[i - 2], 19) ^ (s->w0_63[i - 2] >> 10);
        s->w0_63[i] = s->w0_63[i - 16] + s0 + s->w0_63[i - 7] + s1;
    }
    // Copy current hash value into letters array
    memcpy((void*)loc.letters, (void*)s->hash, SHA224_HASH_BYTESIZE_INTERNAL);
    
    // Compression function
    for(size_t i = 0; i < N_SHA256_Ks; i++){
        ss1 = ROTR_U32(loc.e, 6) ^ ROTR_U32(loc.e, 11) ^ ROTR_U32(loc.e, 25);
        ch = (loc.e & loc.f) ^ ((~loc.e) & loc.g);
        temp1 = loc.h + ss1 + ch + SHA256_K[i] + s->w0_63[i];
        ss0 = ROTR_U32(loc.a, 2) ^ ROTR_U32(loc.a, 13) ^ ROTR_U32(loc.a, 22);
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
    for(size_t i = 0; i < SHA224_HASH_U32WORDS; i++){
        s->hash[i] += loc.letters[i];
    }
    return 0;
}


int sha224_chain(sha224* s, uint8_t* input_data, uint64_t input_bytelen){
    uint32_t bytes_to_move;
    uint8_t* curr_input_data;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha224 instance is NULL.\n");
        return -1;
    }
    if(input_data == NULL){
        printf("ERROR: Pointer to input data is NULL.\n");
        return -1;
    }

    // Process input data in 64-byte (512-bit) chunks 
    curr_input_data = input_data;
    while(true){
        if(s->buffer_idx == SHA224_CHUNK_BYTESIZE){
            sha224_process(s);
            memset(s->buffer_u8, 0, SHA224_CHUNK_BYTESIZE);
            s->buffer_idx = 0;
            continue;
        }
        if(input_bytelen == 0){
            break;
        }
        bytes_to_move = SHA224_CHUNK_BYTESIZE - s->buffer_idx;
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


int sha224_end(sha224* s){
    uint32_t k;
    union{
        uint64_t integer;
        uint8_t array[8];
    } be_u64_src;
    union{
        uint64_t integer;
        uint8_t array[8];
    } be_u64_dest;
    
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha224 instance is NULL.\n");
        return -1;
    }

    // Calculate k value such that:
    // (L * 8) + 1 + k + 64) mod 512
    // where L = data length in bytes
    s->buffer_u8[s->buffer_idx++] = 0x80;
    if((s->data_bytelen % 64) < (SHA224_CHUNK_BYTESIZE - sizeof(uint64_t))){
        // There is room in the current chunk for padding and length
        k = (CALCULATE_SHA256_k(s->data_bytelen * 8) + 1) / 8;
        for(uint8_t i = s->buffer_idx; i < (s->buffer_idx + k); i++){
            s->buffer_u8[i] = 0x00;
        }
        s->buffer_idx += (k - 1);
    }
    else{
        // Not enough room, add some padding and process the current chunk,
        // Then, add padding and the bit length to the next one
        for(uint8_t i = s->buffer_idx; i < SHA224_CHUNK_BYTESIZE; i++){
            s->buffer_u8[i] = 0x00;
        }
        sha224_process(s);
        memset((void*)s->buffer_u8, 0, SHA224_CHUNK_BYTESIZE);
        s->buffer_idx = SHA224_CHUNK_BYTESIZE - sizeof(uint64_t);
    }

    // Append data length in big endian form
    be_u64_dest.integer = s->data_bytelen * 8;
    if(IS_LITTLE_ENDIAN()){
        be_u64_src.integer = s->data_bytelen * 8;
        for(size_t i = 0; i < sizeof(uint64_t); i++){
            be_u64_dest.array[i] = be_u64_src.array[sizeof(uint64_t) - i - 1];
        }
    }    
    for(size_t i = 0; i < sizeof(uint64_t); i++){
        s->buffer_u8[s->buffer_idx++] = be_u64_dest.array[i];
    }

    // Process the last chunk
    sha224_process(s);

    // If in a litte endian system, convert final hash to big endian form
    if(IS_LITTLE_ENDIAN()){
        for(size_t i = 0; i < SHA224_HASH_U32WORDS; i++){
            s->hash[i] = SWAP_ENDIANESS_U32(s->hash[i]);
        }
        s->done = true;
    }
    return 0;
}


int sha224_delete(sha224* s){
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha224 instance is NULL.\n");
        return -1;
    }

    free(s);
    return 0;
}


int sha224_stringify_hash(sha224* s, char* out_buffer){
    union{
        uint32_t integer;
        uint8_t array[sizeof(uint32_t)];
    } u32_buff;
    size_t out_buffer_idx;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha224 instance is NULL.\n");
        return -1;
    }
    
    if(!s->done){
        printf("ERROR: Hash processing is not complete.\n");
        return -1;
    }    

    out_buffer_idx = 0;
    for(size_t i = 0; i < (SHA224_HASH_U32WORDS - 1); i++){
        u32_buff.integer = s->hash[i];
        for(size_t j = 0; j < sizeof(uint32_t); j++){
            sprintf((char*)&out_buffer[out_buffer_idx], "%02x", u32_buff.array[j]);
            out_buffer_idx += 2;
        }
    }
    return 0;
}