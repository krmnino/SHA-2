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
        buff = (char*)calloc(((SHA256_HASH_BYTESIZE * 2)) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        buff = (char*)calloc((SHA256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        buff = (char*)calloc((SHA256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        buff = (char*)calloc((SHA256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        buff = (char*)calloc((SHA256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        buff = (char*)calloc((SHA256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha256_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha256_delete(s);
        free(hex_input_string);
        free(buff);
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
        char* buff;

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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
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
        char* buff;
        
        input_string = "17e8556176fcca2addbdde29";
        output_hash  = "cc6ad0488db0222066f740557b5758a19b30372b302332295d8c3aff";
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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
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
        char* buff;
        
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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
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
        char* buff;
        
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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
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
        char* buff;
        
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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 6
    {
        int ret;
        sha224* s;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        char* buff;
        
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
        
        buff = (char*)calloc((SHA224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha224_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha224_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    return 0;
}


int sha512_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "";
        output_hash  = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 2
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "f47be3a2b019d1beededf5b80c";
        output_hash  = "b94292625caa28c7be24a0997eb7328062a76d9b529c0f1d568f850df6d569b5e84df07e9e246be232033ffac3adf2d18f92ab9dacfc0ecf08aff7145f0b833b";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 3
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "8a5a45e398bac1d9b896b5a2b4e3566b91d80ad20c977ea7450ff2efb521d82f65019ee762e0c85c6cc841";
        output_hash  = "3c704620f4066d79c1ff67752980f39ef3d9c1023fa5a213a5265376b14a15166ffe069b51df7710d8907fef9406bf375d502ce086ac82aff17229aaa7a5a334";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 4
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f79d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d";
        output_hash  = "046e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 5
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043"
			           "aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8";
        output_hash  = "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    
    // Test 6
    {
        int ret;
        sha512* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "afdccc84f257cb768b7ad735edbd1990b6114bad876928ab1279208574bd513ac6beb32bee9192c4bba0425e32ad0e64221371b5ff4f894aecc0c8191aabed39"
			           "51823246cc66c7074aea804e621acb2017bce416acd54c03ba6f77d77f9ac4c479b1b39f33de538860e0f9cd260c370cbc920c983702591ea10f94894c92c022"
			           "65d29dfccc021c8f230b15a3268c3c703a1f520348df98e3cb2789f5289cc89d3f6d58263fd90b64bef23d9709a1c193b8eb1c1e8672f19a603fbde4bcbec57b"
			           "2c0a4ce5336b084e571ed7737754afbe5f7cd3b29ac54d8a87df981db0029d055632e10051c1fc9617154dfd1aacec39575ce0872be092fc6990826aab703983"
			           "e56c7f4140e2cd85256105fe97b1614cc713a965e2c9aa382ed9e391550f813d01418e6ea8d66561aa89693d996bf63fd7279814678a7b86fd43235b57e75d7a"
			           "d038765033a6aa72cd16df84c6e39459b122145b612bef2efe55aa905900b6847dd99faf87598602b78fd199c62021e37a8c840479b2ed775b97e1f8026372a1"
			           "2eac71534cf7e0578f7ca645422a86255deb52d556295cab39912e5afb177b1a0c3a55032b899fba7e66c650e20aac6780c9e597a1972610c3ccfa80eb24b737"
			           "3e0ab189cb16ad73acd499824dc77af10bada511010532ee1ecfae307b93103feca4eeabd6a6f1ca404e87a32c69d70a2720fa0d1f7a688f7522b033536b6d7c"
			           "40917532f1425307625cf87a26f9adfcfca94c51a2feb03aee4e6a511ab4b5346058ade5c6f0bb713c8754d0e47de30db1d003a73399f236b1da42517976d2b0"
			           "7481fd8efdba1151f356036d0d0061866e1d87d57a5416cce74ea2fd17baab38a595cff33ea83defb2526d194a870faf5d1941a31e360444b833f11b9d872813"
			           "1a1b8ade30c128939f01fa9c431cd5cfa34b97dbc848a5e64b0f9774b2e6318bfd9b95157b0db885e2ed13bd9fc69b2f6b3bf2431f91dff9c96dfcd0ffdeaee6"
			           "739d5a60c894d60ca49e1e45078e4918db72bba5cc199bc759d288f72b77876da6aa4089bf5f6b720d9b85fd227ac7d01b7758c776e8c29624c8a3b0dfb9a568"
			           "be49af5607755dfd446caeaa9995fd9f54d23371c6073aaf52d6b5c4c3adee1fe2030f9149de96f67299031713e4d3cfae0cb26d637ded5a0a8526fc7e5a4bd9"
			           "3b5fc9002ca3fca5beaaea0b397132a750ac3f82f752c1df745b5e1eb9c9a4e0f1e5436c59cb79515128cd4db343006e633a4177278ea085b9e2c5f21b00e27a"
			           "2b1de69c775ef443529b13a62862276d0e3f20159d3a719501a2c3424d09ebf011901a5a2f6554c4ea8924de40d78dec7a424324015e1c577322c1d4f6eca98a"
			           "cdc5486c29e6831a417c68bda4a91c32cecb146cfa00881338ea2571bfaf038f8444d69b0cec688d7efb470bfce0ba893362fab4312a9f11778259";
        output_hash  = "014fd2fa6b05c4fca1a5c0753f15c940b5f976b41a40bf6bb14afe839d83a4676173940717bb7e746a2ac77f573e6744cf0002b78b5b7f664e22434e22d0ccd0";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha512_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha512_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    return 0;
}


int sha384_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "";
        output_hash  = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 2
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "20442e1c3f3c88919c39978b78";
        output_hash  = "50bc95b036e0f54d833032a80d45c2ac38b3d29e9c7f72a2eb14781e9241d2a4b8e8dba6ee6f4c9e46a758d5712dbd39";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 3
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "7e80271bb5f2cc7ddae4158658e4e8d06e04a39385da0ecac1cb8e91d68a9bd21ddb7320e79d10e3110758";
        output_hash  = "fa00bc0359a642dcb3559656094eb2fd4f63bc57f0d34abff26df5c54cc63dbeb4eac75905296e7fb69f871e134083f6";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 4
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "93035d3a13ae1b06dd033e764aca0124961da79c366c6c756bc4bcc11850a3a8d120854f34290fff7c8d6d83531dbdd1e81cc4ed4246e00bd4113ef451334daa";
        output_hash  = "8d46cc84b6c2deb206aa5c861798798751a26ee74b1daf3a557c41aebd65adc027559f7cd92b255b374c83bd55568b45";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 5
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "3bf52cc5ee86b9a0190f390a5c0366a560b557000dbe5115fd9ee11630a62769011575f15881198f227876e8fe685a6939bc8b89fd48a34ec5e71e131462b288"
			           "6794dffa68ccc6d564733e67ffef25e627c6f4b5460796e3bce67bf58ca6e8e555bc916a8531697ac948b90dc8616f25101db90b50c3d3dbc9e21e42ff387187";
        output_hash  = "12b6cb35eda92ee37356ddee77781a17b3d90e563824a984faffc6fdd1693bd7626039635563cfc3b9a2b00f9c65eefd";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }

    // Test 6
    {
        int ret;
        sha384* s;
        char* buff;
        char* input_string;
        uint8_t* hex_input_string;
        char* output_hash;
        size_t input_len;
        
        input_string = "f6b1cf75b5cfa4ab323cf04ff13b7a591b23d06ed25f3c04c1baf4c8f7da913cf509c2a5053c4224ce4d0723268cbdf2277672b285c493731ea81799d353fa84"
			           "97baed70c59a4c99b7b950a39470863a69667ff67c9ec981ddb41ffb3d63dd9d034bb79d9df1a95214083199e4efbd770a7a5f005ef5c877236674b6dd1322d0"
			           "624487f6344a43970ec014cbbd114af2313b7b98d4d2779d1b477e925a6ab165dc2ec74133ac01b0cd6b6003c8df15f3072f3988863cbe3aeadea6575d7072a4"
			           "9890de474120cbe478907d07ad6006c2b4e002971b3b8597bbb352cc8d2e4ed5bff234d007ad897d38b8d39f139c06a65fd63f8c3cd7b4fdb44febba93ab2b3f"
			           "78dc31a42d5b23c1346aca95a29cfbe931975630901934b2fd39dae916f0f32becd73d8a5a3282f9952ecab00367cfd151adb14bc008ebfebff98621bf038ce1"
			           "436ac04b363b8c6c828c3bb7de0568a7e7a0b6a573acc22b2218562a36eee0a9a41e22af6a7d2a64240d8573da7fb0b21df6cf05520ea1804d1db4cb22b9d5cb"
			           "377acb7e9e004527a23810aca0dc8d3c1939633404357144699007ce2b6a558e2606238079cdc3fe25964429d824e98b03f0d9fb322918c09dfab6f9fa0b473c"
			           "964a937da4eb8e31d5ad8ab42960abe804a49b2084f3803c12e22b1537a3921bb1cf813cc7628c08d90848133b97bb9b44dc106ba19a8fffefd0cde98a3b2074"
			           "9f1c5686893ba7cb5a2ce70fb7d101ecea20a0a632262f535d4c043f99dad88e88b97b23927dc5c17fa3d070451664231ef8b397dea0477e84df38dd0f88a2b3"
			           "932f56db8b30d03371f46afe8c6fcf870aedb1084e0fbfc98b10d18c924d6629e80551761c5daf6957a71c8135e32761d38603bf2a7b7f7c9b683714ca320c39"
			           "b0c3d3bbec0b4aab5a4450c0e77b55f9a44c0f8419ed6edfdb6ed33d613e7d2b13f24373a4428941a2546d844b3e4197a3c63e21c36b763a74aa0bcffc7a9f47"
			           "38190b66eb0a5472565fdb950934d383f87cf85cd1007ed48da4489146ec5bd548c0925c6a6c93889feb01bbc865f404ccf6a6ffebb16ff64fe5f34ce49e9a1c"
			           "6a6f401dc96f2ec9a48249be30da8a6447bdaed0b8882fe8e2f472c881984265c7af7d70af1c0d7e8eab1a65ea9a7ee990587a98e18ca7f26d592fcdc3e03cf8"
			           "8607b11fc47919ee84efdc799eadb9dcd04f701e0dc5bf5c189d90235280711dd10044f0b1913863afd4f8c3f31c22852e2bfa2ce53c606d0d47ff91d780c81c"
			           "cd209fac1e69532336e4d40892eea02bd3727f8811f8706e71dfe3e1fae6283ca4f2281bb20b537742a7d913232b1d17e6af67fb3801d8a76feda4d962bc7bc6"
			           "7efb4804167e1ea7fba46fab4ddb80929067194d026081602cfaaa42b80aa80282c56730f2ca9efb8863ff97b807b1e2f924ff46191c52e1d38d5c";
        output_hash  = "70a597d1f470d69d7b7d495531c3182704dd60db5c73429fd7108c8ee22d86ed5822adfe6352f28f93023f46cc8d60bb";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);

        s = sha384_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha384_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha384_end(s);
        if(s == NULL){
            return -1;
        }
        
        buff = (char*)calloc((SHA384_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha384_get_stringified_hash(s, buff);
        
        if(strcmp(buff, output_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", buff);
            printf("Expected hash : %s\n", output_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }
        
        sha384_delete(s);
        free(hex_input_string);
        free(buff);
        counter++;
        printf("PASSED #%ld\n", counter);
    }
    return 0;
}


int main(int argc, char* argv[]){
    sha256_test();
    sha224_test();
    sha512_test();
    sha384_test();
    return 0;
}