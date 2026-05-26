#include "../src/sha2.h"
 

int sha224_test(){
    sha224* s;
    char* input_message;
    char* str_output_hash;
    uint8_t* hex_output_hash;
    size_t j;
    int ret;
    char conv_byte[3];
    
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
    
    hex_output_hash = (char*)calloc(SHA224_HASH_BYTESIZE, sizeof(uint8_t));
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
    size_t j;
    int ret;
    char conv_byte[3];
    
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
    
    hex_output_hash = (char*)calloc(SHA256_HASH_BYTESIZE, sizeof(uint8_t));
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
    size_t j;
    int ret;
    char conv_byte[3];
    
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
    
    hex_output_hash = (char*)calloc(SHA384_HASH_BYTESIZE, sizeof(uint8_t));
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


/*
int sha512_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "";
        expected_hash  = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    
    // Test 2
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "f47be3a2b019d1beededf5b80c";
        expected_hash  = "b94292625caa28c7be24a0997eb7328062a76d9b529c0f1d568f850df6d569b5e84df07e9e246be232033ffac3adf2d18f92ab9dacfc0ecf08aff7145f0b833b";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    
    // Test 3
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "8a5a45e398bac1d9b896b5a2b4e3566b91d80ad20c977ea7450ff2efb521d82f65019ee762e0c85c6cc841";
        expected_hash  = "3c704620f4066d79c1ff67752980f39ef3d9c1023fa5a213a5265376b14a15166ffe069b51df7710d8907fef9406bf375d502ce086ac82aff17229aaa7a5a334";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    
    // Test 4
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "c1ca70ae1279ba0b918157558b4920d6b7fba8a06be515170f202fafd36fb7f79d69fad745dba6150568db1e2b728504113eeac34f527fc82f2200b462ecbf5d";
        expected_hash  = "046e46623912b3932b8d662ab42583423843206301b58bf20ab6d76fd47f1cbbcf421df536ecd7e56db5354e7e0f98822d2129c197f6f0f222b8ec5231f3967d";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    
    // Test 5
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043"
			           "aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8";
        expected_hash  = "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    
    // Test 6
    {
        sha512* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
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
        expected_hash  = "014fd2fa6b05c4fca1a5c0753f15c940b5f976b41a40bf6bb14afe839d83a4676173940717bb7e746a2ac77f573e6744cf0002b78b5b7f664e22434e22d0ccd0";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_HASH_BYTESIZE, (SHA512_HASH_BYTESIZE * 2), NO_SKIP, false);

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
        
        output_hash = (char*)calloc((SHA512_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512 PASSED #%ld\n", counter);
    }
    return 0;
}


int sha512_224_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "";
        expected_hash  = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }
    
    // Test 2
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "c5f942edc46407c6019cd926a0";
        expected_hash  = "e180a0d83683cb7e79d812ab5d4288399c78895c6a918e99a2839155";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }

    // Test 3
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "0431a7bfbbec1bb8116a62e1db7e1346862d31ad5110ff1bb9fa169a35dbb43a24e4575604ec8b18e41300";
        expected_hash  = "1e7590e408c038b794e9820b25d011c262062b96d111dccc46dc6783";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }

    // Test 4
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "4cd27324c28364873c6ddbc3e3a7e2cda9e8a72ad2f72201b262f874b8739f30ab60c34334c2e92f9d48533cd8ad2312c3e7c386aaa283b50dec844fa432d636";
        expected_hash  = "ced6081761ff5259f132aa831b7a1b432d093fc857da0eeeb82be71f";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }

    // Test 5
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "9e127870be2431bcb4f4eb4efd5c2a6c5870c55e7a5e3b7503994a4cb136be4ed396887801450f600b22cb772fc00f8b8f0d2690e231a29f69b9f13f24f531e4"
                       "479e45b5e8bc2992fac782567e0d7a59f853ca3a20bf18dbdbf684ac69817e2de075daaed9532659692d3b73530a12df7b8cd9e49ed0463041962c1ce7a24c31";
        expected_hash  = "7e2cf6226623535784c59cd6a7b27dac60ee23fdce8a804dbd6dfedd";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }

    // Test 6
    {
        sha512_224* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "d2fdc48b1452b81292d95db91ef22182c34793129d55d35aee2847766f6590d5e48ebd9bf382be4336431b898ffce687bc43ee1e2b9b35970f3da48ab318feff"
                       "0e1613d499a1365f5d66f0535058f6e8e1f85936d2d4fde2464e4cfd1b9f2b29791c2dfeabb707ac2ec845e1080e3bed5bf03d243a091383bbe4a7974e04019b"
                       "4d2875e1d4cd1b73d2f380f960249bdd52b303ae0c425fc298861d20f54f679cb1c25244bae959fb716f0b6400a40002edc7119df085c8e702bd165fb7864476"
                       "cd732cf00516a98e31c24cea8f9551a255b6d1b88ddc39392310fa1d3db3826fcac26cae5e59f3723d76ad52b6007606b208a9c98c4e9701230731222edd08d0"
                       "d03878446dbc1ff0bb1394661cec56762b43039694e3cb882a2a2336330dbee1065bb97ad9461650d41f6bec6a61db39e8f146e94ea4bd135f023921f44a8ce9"
                       "95b6971a4affbedaaf2499ad4768ec991299da88629855edea16d9aa189c5a32a5ce7bea6af000d675a986715c0771dcd1c4273b77c87c5df4ee6c9b480b1002"
                       "5d2dcbb4de20c58b4d379a005048534b4cf995cc353a18aaa5135bba2ba096a2e55af13e5197f34260553d21cc33782eacc08c0146f8121d240c0dd06a62d45a"
                       "66dd5351695e7343d58bd79e78cfc9cd18a174a44f0a53fe9a61e9a4ac5ab371083f5bb4ce7c2ed6d561d03dfb242e6fb925b57bfb76c2952e9b59009a8e1931"
                       "f2076f3129f90b43886090c7fe3a905eb7d3b74fef4646290941c3aadb08efe04dbdf98e22def1d1150f7f03281ad5e03934e2e7d682c90352db916b18d01ec7"
                       "40e960946032cac9a5f606bb22cbe73e67ce9f0d5630326c32f22a0bf9ec8d2ef4140c0b8cfd7d735f9e8bb59355acc06a2c5487175a69aad10df6522566235c"
                       "90c565bb4d48f2176c8e78ba24c10ead6ad36b1ec207550556b45d084546ca9b3d85d36b4c1a11fdf34e33927d16f44f8e4d4a9aff40e0c7e96fc7f400926931"
                       "23dbbee5317bc26d1d672605455c45ecff205bc3750cf136b4c79cdfff54e767694f8eefa373edae1260b7db249bebcde5d70461cd73719cdc434491ea932e85"
                       "3869ab524a0b7a09f9c150dbc4dccd3a67f7af3baf7d463f8c6c28d2685825d3b7b27dd6cf4a51c6fa1358cfca26d37aad0ac31ac1335968eac8ae6a21aab499"
                       "0fb16d42da395a2d3fdd377de182e5d7e098a8c6ae9c925e1ee13f20be91c31e67eee16012de7e85eda754adaff7eb972827c5071cc0d96b513f44bde7153aab"
                       "e8f242f62043a3182ffa1929dc8dcd03ac4184a5b4a817d5ab68230a433f0188b944f9cdab70b22c2b5cedb8114c7363956d4c671d5b32e553e646cc7b1601fd"
                       "046d6cad5c6b940a09583821f63dc6ff0a348616ffe114e3724113ce36a22052eef3055ddb3e2ffaf273632d3267ac1e341c987a0443a3172ffff4d71dec47ce"
                       "a1602ba7cff16d430e37d4a46ed30e0a3bafeb5bd288c9c8b3aa50aed8fb5fba453b4551e18a352f842bf44e5187d5094675e78111b86d4025c98e1c0ed84e5e"
                       "010dbd24b8136e047dd72bf2848de7647df5f4b46adc77c5aee518e96789fe02fe5dfae8fd93020b20c4e25aaeed2e6309b77bbb84fbcea0768555dd8d1855ee"
                       "64b364655713d88c96797f4c78ad914d1243e25f091d5c19a431adbf258c3d695a9763626f9ad8cf067e6c9189d7f76cbf2293689e4a087761728859daee9dbd"
                       "08925fa9ec30ea1b995c0ff18b724a0639dbf49eed8bba04d4ce4e7151455c30972bc00077ddf6ba769ad23323877164a8f66fc89ee75a0626cf67d03599640b"
                       "2febee30b8aae4f2c7c01c21fb1d54ce33fb6bb05967d1c67efd3c3e2cf39c96f7595201569e9c0cb1575481bb3cdb8b0273501cc512058c05df3383de5aec18"
                       "18fd523afac2074f5ee6e41c0beceee53ee685d58af0dfa0e2fdb566f5d63cdbba5f57a54b1c0b05f6f533ba913675220fda74a3510947493edf2bb0166f7425"
                       "0308ca08f2b79174a00ca923f821588b9cd9844dc26626d0410efb29eb2e7d3f1e7f112c969882e685b4ae1ee6b67f680e6a1d9d840e627d12118f991c1a3d71"
                       "314c96d9e0c9c4a1cd74aa7404fcd2018c16a7594009e598da704dc8513b9d0265f8bfd6775141ee9fd505edf9fb3a9d3f638a4a9d609569c0b49f7e319a853c"
                       "e10af6ed0538df14235e27516dbb9d864fdb2f38441a5c38ed64ec82643ede65ce0aa2e42f86885d839779680a45e502e306fcebdc3f214c89089b9d93308ec6"
                       "53802a849f44230fe40861fa75a0f85a236b5a2a0ed8cceebb28169766767fa799f5f895fd7a9873713a48ce59d4c0d63892b2be82eb4466ab4dc438841a9750"
                       "c7f173dff02ecfd14fb497ad5cea23bd4a036a70df8373fc82fe0d479623c00806fa0329216aaf71a9feb45f26e90b598047ec06cda540f868c4598e439ae118"
                       "7e9a103d3835229aa5a109ac60d95ff003e59e48f65b93a1842610d33486e2c8565802e1dc9810956b24fc5cb2c207cbfb65ea00ffac5440ffac9adf10efaa60"
                       "b7bc42deb5995fab240ff736c3adea328f5037f493a16b1d00de607a80de2328c84f36fc6c43f821f8eb61033ca1f26ce72ceced5840c180b045c86b2c593468"
                       "b2984702a99bc3420e3ea28bc4a706c32c8473b3f6933cb137683b7cbb6bc5679c20ddba13aba8558f93229604c60e7d86dd330e16a2c5f7bccf2273d619bf6e"
                       "af6d61ea537a90a1a26f48eca406f3e31cc194c66073459c6703e319246d08c51209395b1110616f705c7e544b6f9b3d17b7fea27b11a2e6618be8364e6e89b4"
                       "ee7ccfd5f476050721e12c98a10aefd39e48d96c1081c61ed2ef9792fb242a836b4c8a20a4b362b1dc87b87e50ded7ecdafa8deac6cc978be2b85af4d498d479"
                       "b003d103cacf62b5c9d48bcffdf33cd2f35882e546fbff77b76d982680d16ddfe6280e470ed3ec5a11520d52525204cb10e721243716e5287c96b8ee";
        expected_hash  = "856aff6cb91416f97fb2b18276a9b08f835df5909780b994c9382303";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_224_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_224_HASH_BYTESIZE, (SHA512_224_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_224_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_224_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_224_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_224_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_224_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_224_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_224_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_224_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_224_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-224 PASSED #%ld\n", counter);
    }
    return 0;
}


int sha512_256_test(){
    size_t counter;

    counter = 0;
    // Test 1
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "";
        expected_hash  = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }
    
    // Test 2
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "57a10308aa2060aecad05adb2d";
        expected_hash  = "a5208ece1de1342d02ea9ab7cfe537a2c81fa0eaedb427a7b3cb6c291959a6a8";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }
    
    // Test 3
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "381906808394c5f9385a06bc9b6e528095e6f6ac07f0fc755e13594768b7686766e897d662576178c2a17c";
        expected_hash  = "22ea5298af2aa311a5b53f8b2838dfc008ae470bf96d2bb6794735ea72108879";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }

    // Test 4
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "d2bc0ce7217ff2e944e1ae47ad5873bf391f1b0cc07f6151eb4c50bb45b2fb6295326f716ce7e687fa0e3d5d25c5a8a8dd13a541a9292e8386e733f4f2a24728";
        expected_hash  = "9c1fea5786702d027bb5b66b3fa92de34621a8626982ec21c0ecf8daa79dea05";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }

    // Test 5
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "bc8173c878ca60e9a0f823f9a589d4ff84547b389b117fb6bb1b614e7e75a9b1db0b21d9f73b42a73e94eccab3de5ae2845a54e5e24ba6c20fb4d245b964023b"
                       "863040d6f080e953530d5fd944e8ffa525bf5364f65c88e06e6e22df4b8cee48e67738880a9f3f3406e9e6f001b0ac8f8e0ade7c814c0c5800d0b9e4ddf55622";
        expected_hash  = "f691d01ee9ab675f3872313b77e6a4543c71e3e89aa94c48f91d6ee7fa1ab4fb";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }

    // Test 6
    {
        sha512_256* s;
        char* input_string;
        char* expected_hash;
        char* output_hash;
        uint8_t* hex_input_string;
        uint8_t* hex_expected_hash;
        uint8_t* hex_output_hash;
        size_t input_len;
        int ret;
        
        input_string = "7dd8ff559cdc0f0d0053055cc142e015fba8b4cc7f60fcddc94832b133a39d3c68bc6bca1acdfffcf81e8c0dda71e35a3f9e8922fa7b0d8a28fe98e465a6c630"
                       "4016b4e3ec045be838511ce5c0799bbf652ed160fc405db843c01b011965f848ee2e05297849cadaa734dc6bdc22b24b56a0b40fec78956f02d6e391b6a9dc8b"
                       "5a4c84232766f4d82f0ff5279434cd07f83c59b634eb5cb74d87171ca43a1a016cb85959612182edb7298ea1517697f9344ae9dd3b615b990c1de0284ae059b2"
                       "0db9ad538f441c1e28cbd0627cb1b52bf3118b0c69a23a1c27de653f126341a72399a89a17956975683de3f17badd2a51bda68cc2675a0498613cfe8638a7be7"
                       "979e71b563dd12f960c7eed6b832946d95eda7a4daa43526120345aca51eaf7a5211312cd9e3beb2f8b1199a9908a38d4a92721dedf5a2beb1f8f01141e88469"
                       "3b3a0f88e37116a919428ec488f6a80d2111eebdc8318f164c38f7a19dada3bb3960344fe84dc2e5a9c372dcecc64bf301b1450fd120a338cc0c83e42238b478"
                       "36ccc70c5040696e917cf06a2d3e3349d4bb9f987189872b17bcbc6138505ea819c7f1448212b34dbab52df7b3270917817723e21035e3f71790c9a048bc4954"
                       "ca97da81e88b4a890bb6540ae5487463f02dfa7417ed5ea5b2d0d329b8451e843084a94ae973d32a6bc68b2c2d6b1d3709254bd6ec77a03bd2c30185f2b3853e"
                       "35d88728ed91f939c42ffae4f256ab9ab4a63f91f99b52c45eb27c3b5cce258cc0d99ba25cae61bdfd37cbba9dd2c795d9fafe2ca5231c453ee56bd3605da775"
                       "bad10e409f92b6befe27233694a7192e6067af2f57d5a5c85aa4f7d5652ab2020906078a1c059e45af472de1409d486f31367b22797b96549a3748cad3fbef39"
                       "96c1af093ccfc158f8de0e42097cfd6034af898e72db96f2e6e5853a1199062449492d4467b7c902c136f1e2580bdf08521902fbaabe4ea926f8d7ab89cc9ecb"
                       "0ae8aac306875b48f295fc479313976f71be0def89eb658142b665a7a25b5f34c2e44e0f7f052234734457fb245ccc9d7ae4d3f4772c8482226858b5c410f369"
                       "578640af3cfac3cd2c8b2b8671ae279b56d47b91dc4753b5ae55d75e57b1ff72b316a92ba32de91b05b1a06ee4d15070ebd62e4f20057921cfc70b28c3072e55"
                       "bcdcb00c1e683a27e700dd3de38cee24233114b4ab2e9fce6b041b9d71da251c5c1f7ed914715ef8b8be0b7ad8a9a9c0e52f544ae58a6cc56b553045c7f28fcf"
                       "7a293a1aed11fe96623451ae2aee2b4a1816179937e0890db80272a72e161274fe400d581010c20acbaad860412419cda62f842807fa9dae3853084b0f105615"
                       "cfad1f19e736515bdd67c71885131e4e76c2c47fbe9e51b1d5901bb9d0a604b9d7b897e8d94b54917eb5475f5e82e0d77017fe26c5954d1d7600d27adba1c469"
                       "fda89e4a4e1672b598da80bb343a076f7c755ba682a738fa03ec561596c83d2c29c75bc9ae6054ce121f99b76f043c1f822603855f9bbb51639cce126be5180a"
                       "435bf7ec62f1a1e4d4ccbbd877a627ee6a701d4ec33b7d29805863fac1befc0b34ad993bd0910200c6290da8b4e86fe41c9cd186164d278a41683d53ff1d9238"
                       "e2056a3f61081f28d07eb8ae8f94bc0981f149b7bf9a607c8e1383a88fc8829836ab927f7d1d9f67da12e3726e70b8667fb9aa6828ead1084fa35e7ed8877333"
                       "18e638848d9a2bc2cc2eb77dba460902ff3a1f22b80521356c5ef55f42240e1271ff84d4f7456a438e1a5c56dcdc57e5eabecd6cd7b2f90cce8d71d23565fa3c"
                       "273e9ff925e605f1081ef9853afa4b18268bdfceedbb01935b77f9601914dfb924ebb17b7d47a3d42382b6933e6a8ca29de97bd062e6e0d4fc66b68f56f76792"
                       "4e4ee1e0692fedf5c58dbc074ff3c38b3522cafb9ffc3fd79aa0cfea54d738ce8faf58b250658a5bd7883369d45c98dcd87df3d60ac4c5a21b6e6df67c7bfa75"
                       "ce553e789ab2230e42bb4342376eb29c6d411eea0c081b3f6918b83d34ad5690f389babbaede6017ec6e1218dff1bad3dcb775bd0e8ee8b66ae6d746e533f326"
                       "e593f402f6b1e87dbfe9cb7634ad57890d271dd9761fd50d0820f399f8d67b3f8ebb15d5d9f36448a27394e19e6932c7e7d841c6ad838a4e290d33bfd35e93e3"
                       "d54945bcbf6b7b817c5695e385eff3945414070a1c82ae81b7f6c03fe093e51ba284ab4010e2d62f37d8f803510541f93c21972f2ae4e9ac9923c1a1863d19ee"
                       "ddb570e835201d5aba42e2ca6a74c4fd85481abd3e70e5d9b7dc5f6e2c23d7656f24bb3d94edf70aeddc7dbe390325a818d1b83ac2ef470ff969c22d3c0ec687"
                       "3e19b5c696110c48b8edf169247c0c02dd0498301d2aba57471111661dc68e5c33dc860ba353051b03bf665394a52014bc29e326b7e6e4b8891e75a13713d8ec"
                       "36b45594247c8a8cb6980302f2480ae59e87c0a5f8ee6d3aa7d61567f2bd4c4030eb4aea7f5442a2b9c1f000a42b727d696758344809fee589821a3fb68b915f"
                       "07c78f941ea3d665f48256d51417fee50711d35b0ffe3fc21869abb2eb465051a591491a6731eddd50225d07a8d359245ecd58a2b596d7d83ad5f147f9b6301f"
                       "f090a305c4c63013b3eb2c20ca29294258e30f92a2996f2fd80c138648a3dad0d20ec3db9c29470e0723eca8e1df1748dc9a21b23ecfaed0db573af740d5f56c"
                       "3251d1275723d9d63213c42555beca3dd13cb68af2ff3dc229fe8e234a132afcf7a2f66e5c7c8e741e03dd218d8eeb29210ff5a324f3c30dac493691cc272186"
                       "0b49593a15fc10efb13a5e23f3172115b35c07843e71e9ba4a805bc930d78115558e2412e96a044fd50270b4ee2015086f6a14b5a64257d0edea2454dcecf2ae"
                       "bdb97c7f4090159d71a13b5be6736e0a3d8343bfc62eb4577cd0bab93a2e1e5b2b118b088334e9e06c60e6a043d6d52305edbc2904fca858df7a4480";
        expected_hash  = "1544acd8bc55003ed7b60993c398baae11c8e2654a6de87b73b0d49f0b102cc3";
        input_len = strlen(input_string);
        hex_input_string = (uint8_t*)calloc((input_len / 2), sizeof(uint8_t));
        char_str_2_hex_str(input_string, input_len, hex_input_string, (input_len / 2), input_len, NO_SKIP, false);
        hex_expected_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        char_str_2_hex_str(expected_hash, (SHA512_256_HASH_BYTESIZE * 2), hex_expected_hash, SHA512_256_HASH_BYTESIZE, (SHA512_256_HASH_BYTESIZE * 2), NO_SKIP, false);

        s = sha512_256_init();
        if(s == NULL){
            return -1;
        }
        
        ret = sha512_256_chain(s, hex_input_string, (input_len / 2));
        if(s == NULL){
            return -1;
        }

        ret = sha512_256_end(s);
        if(s == NULL){
            return -1;
        }
        
        output_hash = (char*)calloc((SHA512_256_HASH_BYTESIZE * 2) + 1, sizeof(char));
        sha512_256_get_stringified_hash(s, output_hash);
        
        if(strcmp(output_hash, expected_hash) != 0){
            printf("!!! ERROR !!!\n");
            printf("Input data    : %s\n", input_string);
            printf("Output hash   : %s\n", output_hash);
            printf("Expected hash : %s\n", expected_hash);
            printf("!!! ERROR !!!\n");
            return -1;
        }

        hex_output_hash = (uint8_t*)calloc(SHA512_256_HASH_BYTESIZE, sizeof(uint8_t));
        sha512_256_get_hash(s, hex_output_hash);
        
        for(size_t i = 0; i < SHA512_256_HASH_BYTESIZE; i++){
            if(hex_expected_hash[i] != hex_output_hash[i]){
                printf("!!! ERROR !!!\n");
                printf("Input data       : %s\n", input_string);
                printf("Hash byte index :  %ld\n", i);
                printf("Output hash      : %x\n", hex_output_hash[i]);
                printf("Expected hash    : %x\n", hex_expected_hash[i]);
                printf("!!! ERROR !!!\n");
                return -1;
            }
        }

        sha512_256_delete(s);
        free(hex_input_string);
        free(hex_expected_hash);
        free(hex_output_hash);
        free(output_hash);
        counter++;
        printf("SHA-512-256 PASSED #%ld\n", counter);
    }
    return 0;
}
*/

int main(int argc, char* argv[]){
    sha224_test();
    sha256_test();
    sha384_test();
    //sha512_test();
    //sha512_224_test();
    //sha512_256_test();
    return 0;
}