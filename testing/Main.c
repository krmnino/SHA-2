#include "../src/sha256.h"

#define NO_SKIP 0
#define SKIP 1

int char_str_2_hex_str(const char* input, size_t input_len, void* output, size_t output_len, size_t n_chars, size_t skip, bool little_endian){
    uint8_t* output_bytes = (uint8_t*)output;
    size_t byte_i = 0;
    uint8_t str_char = 0;
    uint8_t skipper = 0;
    if(little_endian){
        skipper = skip || (n_chars % 2);
    }
    // Clear output buffer
    memset(output_bytes, 0, output_len);
    if(little_endian){
        byte_i = output_len - 1 - (output_len - ((n_chars + 1) / 2));
    }
    else{
        byte_i = 0;
    }
    for(size_t i = 0; i < n_chars; i++){
        if((i + skipper) % 2 == 0 && i != 0){
            if(little_endian){
                byte_i--;
            }
            else{
                byte_i++;
            }
        }
        str_char = input[i];
        switch (str_char) {
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            str_char = ((str_char & 0x0F) | 0x08) + 1;
            break;        
        default:
            str_char = str_char & 0x0F;
            break;
        }
        if((i + skipper) % 2 == 0){
            output_bytes[byte_i] = (output_bytes[byte_i] | str_char) << 4;
        }
        else{
            output_bytes[byte_i] = output_bytes[byte_i] | str_char;
        }
    }
    return 0;
}

int sha256_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "";
        output_hash  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha256_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA256_HASH_BYTESIZE * 2, sizeof(char));
        sha256_stringify(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 2
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "68511cdb2dbbf3530d7fb61cbc";
        output_hash  = "af53430466715e99a602fc9f5945719b04dd24267e6a98471f7a7869bd3b4313";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha256_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA256_HASH_BYTESIZE * 2, sizeof(char));
        sha256_stringify(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 3
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95";
        output_hash  = "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha256_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA256_HASH_BYTESIZE * 2, sizeof(char));
        sha256_stringify(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 4
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "33fd9bc17e2b271fa04c6b93c0bdeae98654a7682d31d9b4dab7e6f32cd58f2f148a68fbe7a88c5ab1d88edccddeb30ab21e5e";
        output_hash  = "cefdae1a3d75e792e8698d5e71f177cc761314e9ad5df9602c6e60ae65c4c267";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha256_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA256_HASH_BYTESIZE * 2, sizeof(char));
        sha256_stringify(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
}

int main(int argc, char* argv[]){
    sha256_test();
    return 0;
}