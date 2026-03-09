#include "../src/sha256.h"

int sha256_test(){

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
    
    char* buff;
    buff = (char*)calloc(SHA256_HASH_BYTESIZE * 2, sizeof(char));
    sha256_stringify(s, buff);

    printf("%s\n", buff);
    
    sha256_delete(s);

    return 0;
}