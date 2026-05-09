#ifndef UTILS
#define UTILS


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_BYTES_IN_LINE 32
#define MAX_BYTES_IN_WORD 4


int hex_str_2_bin_str(char*, uint8_t*, size_t);
int bin_str_2_hex_str(uint8_t*, char*, size_t);
int hex_print(uint8_t*, size_t, size_t);
int compare_uint8_t_arrays(uint8_t*, uint8_t*, size_t);


#endif