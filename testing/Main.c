#include "../src/sha2.h"

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
        sha256_stringify_hash(s, buff);
        
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
        sha256_stringify_hash(s, buff);
        
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
        sha256_stringify_hash(s, buff);
        
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
        sha256_stringify_hash(s, buff);
        
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
        sha256_stringify_hash(s, buff);
        
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
        sha256_stringify_hash(s, buff);
        
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
    return 0;
}

int sha224_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "";
        output_hash  = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha224_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA224_HASH_BYTESIZE * 2, sizeof(char));
        sha224_stringify_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 2
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "3ec0aa8d30d5ed825b77dc7095f421b1e608158797a377ff8bed641b";
        output_hash  = "3108321eb7ff857f6aae69101b937f32a51ea279a6c14ba5232ac8c1";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha224_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA224_HASH_BYTESIZE * 2, sizeof(char));
        sha224_stringify_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 3
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "f015ec83944f03292463c4345fdb1c26d1ea07645facbc9520ae244b6eb191e53dabadb4ac0fb15cda4ed77dfb9e1193abfafb1b81";
        output_hash  = "459e40b3fbd612912f0217c60099379ce077cd02505871b0c9c14e7a";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha224_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA224_HASH_BYTESIZE * 2, sizeof(char));
        sha224_stringify_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 4
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "a3310ba064be2e14ad32276e18cd0310c933a6e650c3c754d0243c6c61207865b4b65248f66a08edf6e0832689a9dc3a2e5d2095eeea50bd862bac88c8bd318d";
        output_hash  = "b2a5586d9cbf0baa999157b4af06d88ae08d7c9faab4bc1a96829d65";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha224_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA224_HASH_BYTESIZE * 2, sizeof(char));
        sha224_stringify_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 5
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "a67e008f13a29021d1493c7ddb0e7f4126a786f9e01991eff52c9b45d81d3d40"
                       "8094d0e7b1d5d2cd7c3a8a2b09e1ef3194a2c79eb6440c8fe6f093943fe5f009"
                       "846e94a46111384af30a7f278bf8d6fdafd59fbc622b9054a68555c73e247d82"
                       "b8f493edabbf8b413e9f619ae9b9fc4d8028587b6d38e4e63cd529045e43ad52"
                       "260f17eb1845935963e378abac8e29c70d8439025ed2d2eeb3c7577325a84822"
                       "d6a566c52f0c183b6cbd0e835bde241660cf897abd6020141042263e1dbc1699"
                       "ce9fc9a4787ce28e601469497e10b6e081f3910a134c97ff5d30e08acee7de60"
                       "18e688b07cfdb8fb48d2d2269e8ea7ce76d699dbe6fdff58a278cb82bf926a1e"
                       "bc61eb10c2f8642a2bde914242bfbf874962e815c1db20c6e5022f4b7823807c"
                       "c0f73aedd3d3acc21120eec4f20bc5b4027dc8df294ec1f230b656108104e922"
                       "2e92bc6e35f8596c038031d436da83fca7117f61a8beac838a7c87f7639b6db7"
                       "0d19babc72cd33cf07e6a19c9794bf08420556c4c593a722fc3c0928a552d3e4"
                       "66737cfe12bc0194283a87419ca1427fda41953009357b778cde25cccf90e550"
                       "408a4a5d9b2c8d626b642beece6ad40a78ad84ccfa0df029444a230b69bc69a3"
                       "a3456c0197859de2da4cd5c9";
        output_hash  = "f6430298cd0e80d919f22cf1094988241f84b8753838afead0156940";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha224_end(s);
        if(s == NULL){
            return -1;
        }
        
        char* buff;
        buff = (char*)calloc(SHA224_HASH_BYTESIZE * 2, sizeof(char));
        sha224_stringify_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    return 0;
}

int main(int argc, char* argv[]){
    sha256_test();
    sha224_test();
    return 0;
}