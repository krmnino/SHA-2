#include <stdint.h>
#include <string.h>


typedef struct TestVector TestVector;
struct TestVector{
	uint64_t bitlen;
	char* hash;
	char* msg;
};
