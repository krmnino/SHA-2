#include "Utils.h"


int hex_str_2_bin_str(char* input_buffer, uint8_t* output_buffer, size_t input_charlen){
    uint8_t byte;

    // Validate input
    if(input_buffer == NULL){
        printf("ERROR: Pointer to input buffer is NULL.");
        return -1;
    }
    if(output_buffer == NULL){
        printf("ERROR: Pointer to output buffer is NULL.");
        return -1;
    }
    if(input_charlen == 0){
        printf("ERROR: Input buffer character length value is 0.");
        return -1;    
    }

    for(size_t i = 0; i < input_charlen; i++){
        switch (input_buffer[i]) {
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
            byte = ((input_buffer[i] & 0x0F) | 0x08) + 1;
            break;        
        default:
            byte = input_buffer[i] & 0x0F;
            break;
        }
        if((i % 2) == 0){
            output_buffer[(i / 2)] = byte << 4;
        }
        else{
            output_buffer[(i / 2)] = output_buffer[(i / 2)] | byte;
        }
    }
    return 0;
}


int bin_str_2_hex_str(uint8_t* input_buffer, char* output_buffer, size_t input_bytelen){
    size_t output_idx;
    char loc_buff[3];

    // Validate input
    if(input_buffer == NULL){
        printf("ERROR: Pointer to input buffer is NULL.");
        return -1;
    }
    if(output_buffer == NULL){
        printf("ERROR: Pointer to output buffer is NULL.");
        return -1;
    }
    if(input_bytelen == 0){
        printf("ERROR: Input buffer byte length value is 0.");
        return -1;    
    }

    output_idx = 0;
    for(size_t i = 0; i < input_bytelen; i++){
        sprintf(((char*)&output_buffer[output_idx]), "%02x", input_buffer[i]);
        output_idx += 2;
    }
    return 0;
}


int hex_print(uint8_t* input_buffer, size_t data_len, size_t addr_offset){
    char hex_str[3];
    size_t bytes_to_print;

    // Validate input
    if(input_buffer == NULL){
        printf("ERROR: Pointer to input buffer is NULL.\n");
        return -1;
    }

    for(size_t i = 0; i < data_len; i += 4){
        bytes_to_print = data_len - i; 
        if(bytes_to_print > MAX_BYTES_IN_WORD){
            bytes_to_print = MAX_BYTES_IN_WORD;
        }
        if(i % MAX_BYTES_IN_LINE == 0){
            if(i != 0){
                printf("\n%016lx: ", i + addr_offset);
            }
            else{
                printf("%016lx: ", i + addr_offset);
            }
        }
        for(size_t j = 0; j < bytes_to_print; j++){
            memset(hex_str, 0, sizeof(hex_str));
            bin_str_2_hex_str((uint8_t*)&input_buffer[i + j], hex_str, 1);
            printf("%s", hex_str);
        }
        printf(" ");
    }
    printf("\n");
    
    return 0;
}


int compare_uint8_t_arrays(uint8_t* arr1, uint8_t* arr2, size_t bytelen){
    // Validate input
    if(arr1 == NULL){
        printf("ERROR: Pointer to input array 1 is NULL.\n");
        return -1;
    }
    if(arr2 == NULL){
        printf("ERROR: Pointer to input array 2 is NULL.\n");
        return -1;
    }

    // Loop through both arrays to figure out which array is lesser than the other, byte-size.
    for(size_t i = 0; i < bytelen; i++){
        if(arr1[i] < arr2[i]){
            return -1;
        }
        else if (arr1[i] > arr2[i]){
            return 1;
        }
    }
    return 0;
}