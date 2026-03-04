#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static uint32_t SHA256_INIT_HASH[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};
#define SHA256_HASH_BYTESIZE (sizeof(SHA256_INIT_HASH))
#define SHA256_HASH_BITSIZE (SHA256_HASH_BYTESIZE * 8)
#define SHA256_HASH_U32WORDS (SHA256_HASH_BYTESIZE / sizeof(uint32_t))
#define SHA256_CHUNK_BITSIZE (SHA256_HASH_BITSIZE * 2)
#define SHA256_CHUNK_BYTESIZE (SHA256_CHUNK_BITSIZE / 8)


static uint32_t SHA256_K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
#define N_SHA256_Ks (sizeof(SHA256_K) / sizeof(uint32_t))


#define CALCULATE_SHA256_k(input_bitlen) \
        (SHA256_CHUNK_BITSIZE - (((input_bitlen) + 1 + 64) % SHA256_CHUNK_BITSIZE))


typedef struct sha256 sha256;
struct sha256{
    struct {
        union{
            uint32_t w0_63[N_SHA256_Ks];
            uint32_t w0_15[N_SHA256_Ks / 4];
            uint8_t buffer_u8[SHA256_CHUNK_BYTESIZE];
        };
    };
    
    uint32_t hash[SHA256_HASH_U32WORDS];
    uint64_t data_bytelen;
    bool big_endian;
    bool done;
    uint8_t buffer_idx;
};


sha256* sha256_init();
int sha256_chain(sha256*, uint8_t*, uint64_t);
int sha256_end(sha256*);
int sha256_delete(sha256*);
int sha256_display(sha256*);


uint32_t rightrotate(uint32_t data, uint64_t n_bits){
    uint32_t shifted;
    uint32_t rotated;
    uint32_t combined;
    
    shifted = data >> n_bits;
    rotated = data << ((sizeof(uint32_t) * 8) - n_bits);
    combined = rotated | shifted;
    return combined;
}


sha256* sha256_init(){
    sha256* s;
    uint32_t endianess;
    uint8_t* endianess_ptr;

    // Allocate sha256 instance
    s = (sha256*)calloc(1, sizeof(sha256));
    if(s == NULL){
        printf("ERROR: Could not allocate memory for sha256 instance.\n");
        return NULL;
    }
    // Initialize hash array
    memcpy((void*)s->hash, (void*)SHA256_INIT_HASH, SHA256_HASH_BYTESIZE);

    // Figure out endianess
    endianess = 0x01;
    endianess_ptr = (uint8_t*)&endianess;
    if(endianess_ptr[3] == 0x01){
        s->big_endian = true;
    }
    else{
        s->big_endian = false;
    }
    
    return s;
}


int sha256_process(sha256* s){
    union{
        uint32_t letters[SHA256_HASH_U32WORDS];
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
    union{
        uint32_t integer;
        uint8_t array[4];
    } be_u32_src;
    union{
        uint32_t integer;
        uint8_t array[4];
    } be_u32_dest;
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
        printf("ERROR: Could not allocate memory for sha256 instance.\n");
        return -1;
    }

    // If in little-endian system, we need to convert the word to big-endian form
    if(!s->big_endian){
        for(size_t i = 0; i < (N_SHA256_Ks / 4); i++){
            be_u32_src.integer = s->w0_15[i];
            for(size_t j = 0; j < sizeof(uint32_t); j++){
                be_u32_dest.array[j] = be_u32_src.array[sizeof(uint32_t) - j - 1];
            }
            s->w0_15[i] = be_u32_dest.integer;
        }
    }

    // Extend first 16 words to the remaining 48 words
    for(size_t i = 16; i < N_SHA256_Ks; i++){
        s0 = rightrotate(s->w0_63[i - 15], 7) ^ rightrotate(s->w0_63[i - 15], 18) ^ (s->w0_63[i - 15] >> 3);
        s1 = rightrotate(s->w0_63[i - 2], 17) ^ rightrotate(s->w0_63[i - 2], 19) ^ (s->w0_63[i - 2] >> 10);
        s->w0_63[i] = s->w0_63[i - 16] + s0 + s->w0_63[i - 7] + s1;
    }
    // Copy current hash value into letters array
    memcpy((void*)loc.letters, (void*)s->hash, SHA256_HASH_BYTESIZE);
    
    // Compression function
    for(size_t i = 0; i < N_SHA256_Ks; i++){
        ss1 = rightrotate(loc.e, 6) ^ rightrotate(loc.e, 11) ^ rightrotate(loc.e, 25);
        ch = (loc.e & loc.f) ^ ((~loc.e) & loc.g);
        temp1 = loc.h + ss1 + ch + SHA256_K[i] + s->w0_63[i];
        ss0 = rightrotate(loc.a, 2) ^ rightrotate(loc.a, 13) ^ rightrotate(loc.a, 22);
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
    for(size_t i = 0; i < SHA256_HASH_U32WORDS; i++){
        s->hash[i] += loc.letters[i];
    }
    return 0;
}


int sha256_chain(sha256* s, uint8_t* input_data, uint64_t input_datalen){
    uint32_t bytes_to_move;
    uint8_t* curr_input_data;

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha256 instance is NULL.\n");
        return -1;
    }
    if(input_data == NULL){
        printf("ERROR: Pointer to input data is NULL.\n");
        return -1;
    }

    // Process input data in 64-byte (512-bit) chunks 
    curr_input_data = input_data;
    while(true){
        if(input_datalen == 0){
            break;
        }
        if(s->buffer_idx == SHA256_CHUNK_BYTESIZE){
            sha256_process(s);
            memset(s->buffer_u8, 0, SHA256_CHUNK_BYTESIZE);
            s->buffer_idx = 0;
            continue;
        }
        bytes_to_move = SHA256_CHUNK_BYTESIZE - s->buffer_idx;
        if(bytes_to_move > input_datalen){
            bytes_to_move = input_datalen;
        }
        memcpy((void*)(s->buffer_u8 + s->buffer_idx), (void*)curr_input_data, bytes_to_move);
        curr_input_data += bytes_to_move; 
        s->buffer_idx += bytes_to_move;
        s->data_bytelen += bytes_to_move;
        input_datalen -= bytes_to_move;
    }
    return 0;
}


int sha256_end(sha256* s){
    uint32_t k;
    union{
        uint64_t integer;
        uint8_t array[8];
    } be_u64_src;
    union{
        uint64_t integer;
        uint8_t array[8];
    } be_u64_dest;
    union{
        uint32_t integer;
        uint8_t array[4];
    } be_u32_src;
    union{
        uint32_t integer;
        uint8_t array[4];
    } be_u32_dest;
    
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha256 instance is NULL.\n");
        return -1;
    }

    // Calculate k value such that:
    // (L * 8) + 1 + k + 64) mod 512
    // where L = data length in bytes
    s->buffer_u8[s->buffer_idx++] = 0x80;
    if((s->data_bytelen % 64) < (SHA256_CHUNK_BYTESIZE - sizeof(uint64_t))){
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
        for(uint8_t i = s->buffer_idx; i < SHA256_CHUNK_BYTESIZE; i++){
            s->buffer_u8[i] = 0x00;
        }
        sha256_process(s);
        memset((void*)s->buffer_u8, 0, SHA256_CHUNK_BYTESIZE);
        s->buffer_idx = SHA256_CHUNK_BYTESIZE - sizeof(uint64_t);
    }

    // Append data length in big endian form
    if(s->big_endian){
        be_u64_dest.integer = s->data_bytelen * 8;
    }
    else{
        be_u64_src.integer = s->data_bytelen * 8;
        for(size_t i = 0; i < sizeof(uint64_t); i++){
            be_u64_dest.array[i] = be_u64_src.array[sizeof(uint64_t) - i - 1];
        }
    }    
    for(size_t i = 0; i < sizeof(uint64_t); i++){
        s->buffer_u8[s->buffer_idx++] = be_u64_dest.array[i];
    }

    // Process the last chunk
    sha256_process(s);

    // If in a litte endian system, convert final hash to big endian form
    if(!s->big_endian){
        for(size_t i = 0; i < SHA256_HASH_U32WORDS; i++){
            be_u32_src.integer = s->hash[i];
            for(size_t j = 0; j < sizeof(uint32_t); j++){
                be_u32_dest.array[j] = be_u32_src.array[sizeof(uint32_t) - j - 1];
            }
            s->hash[i] = be_u32_dest.integer;
        }
        s->done = true;
    }

    return 0;
}


int sha256_delete(sha256* s){
    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha256 instance is NULL.\n");
        return -1;
    }

    free(s);
    return 0;
}


int sha256_display(sha256* s){
    union{
        uint32_t integer;
        uint8_t array[4];
    } u32_buff;
    uint8_t lower_nibble;
    uint8_t upper_nibble;
    char hex_str[3];

    // Validate input
    if(s == NULL){
        printf("ERROR: Pointer to sha256 instance is NULL.\n");
        return -1;
    }
    
    if(!s->done){
        printf("ERROR: Hash processing is not complete.\n");
        return -1;
    }    

    memset(hex_str, 0, sizeof(hex_str));
    for(size_t i = 0; i < SHA256_HASH_U32WORDS; i++){
        u32_buff.integer = s->hash[i];
        for(size_t j = 0; j < sizeof(uint32_t); j++){
            printf("%02x", u32_buff.array[j]);
        }
    }
    printf("\n");
    return 0;
}


int main(int argc, char* argv[]){
    int ret;
    sha256* s;    
    
    s = sha256_init();
    if(s == NULL){
        return -1;
    }

    // Loop through all the elements in argv
    for(size_t i = 1; i < argc; i++){
        sha256_chain(s, argv[i], strlen(argv[i]));
    }
    sha256_end(s);
    
    sha256_display(s);
    sha256_delete(s);

    return 0;
}