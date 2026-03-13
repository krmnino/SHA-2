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

    // Test 5
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509";
        output_hash  = "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa";
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

    // Test 6
    {
        int ret;
        sha256* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "5f664be0c0f3d2fc9a1a7ed6b515ef9c52ad1c7fb3acf2c2de943e109f91cc12"
                       "ccadd041cc4386f95ab616cf8762ba25fed322fc8c351809e00c600a8f26e25a"
                       "5bcd0bc3b44170947f65b4f417b8ac769187c2ee4561978289cced04c036c37f"
                       "942ec10f7fd4d7f6908e22ed6cfd0fb89330c2fde417b956643aaca53baab8a8"
                       "ff38bdcd35e60547159b26618e1b29128a35ebd2733fc4adf6bf6796076b09fd"
                       "2554c6a4df5e40ae97f389f986f843ad00000515f9c001aec9c4e47e2c60fea7"
                       "8de8a33c8423d1539dfe125c5b7ea4b17cf8d86e7f84b88264afec06b370dfce"
                       "bf5e1d3e2c1f005faf248b321593964587852b830c7231504fe947d6a385f399"
                       "441cfc52df3914fa55cdba25bd215f91a80fc8ffa872b34113dbbd9504868331"
                       "a38c081fa659574b186169db590f48be67fe75885b6c877d37ec16ebde5ad7be"
                       "6414084e88670f7b7f485efcf44599f44cbbfbc62e48f62b438319823aeb3767"
                       "101ec6868e4c85b113ea623193ab9a5ae0ac226328ee4674bf0a90ff1f20eb54"
                       "2e110870bfee01165ab03c2240299319aa3ab1045247bf7f34e8410d96e13aae"
                       "465597b42336cad2de00b67602a7cb5832cd7253b239ab752a85f452a6166e9d"
                       "e0523bf9c20c2a0c274396d5";
        output_hash  = "044d823532092c22a4b48181cfb2c796e1f5b98bcd713a21f70b5afcceef1d73";
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