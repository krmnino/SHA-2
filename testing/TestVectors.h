#include <stdint.h>
#include <string.h>


typedef struct Testcase Testcase;
struct Testcase{
    char* original_input_data;
    uint8_t* input_data;
    uint8_t* expected_hash;
    size_t input_data_len;
};