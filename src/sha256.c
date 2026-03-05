#include "sha256.h"


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