#include "../src/sha256.h"

int sha256_test(){
    // Test 1
    {
        int ret;
        sha256* s;
        char* input_data;
        char* output_hash;

        input_data = "";
        
        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, input_data, strlen(input_data));
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
        
        printf("%s\n", buff);
        
        sha256_delete(s);
    }

    // Test 2
    {
        int ret;
        sha256* s;
        char input_string[13];
        char* output_hash;
        
        input_string[0] = 0x9b;
        input_string[1] = 0xaf;
        input_string[2] = 0x69;
        input_string[3] = 0xcb;
        input_string[4] = 0xa3;
        input_string[5] = 0x17;
        input_string[6] = 0xf4;
        input_string[7] = 0x22;
        input_string[8] = 0xfe;
        input_string[9] = 0x26;
        input_string[10] = 0xa9;
        input_string[11] = 0xa0;
        input_string[12] = 0x00;
        
        s = sha256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha256_chain(s, input_string, strlen(input_string));
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
        
        printf("%s\n", buff);
        
        sha256_delete(s);
    }
}

int main(int argc, char* argv[]){
    sha256_test();
    return 0;
}