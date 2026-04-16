#ifndef CONTEXT
#define CONTEXT

#include <stdint.h>
#include <string.h>
#include "../res/ArgParsing_C.h"
#include "../src/sha2.h"


static struct Context{
    ArgParsing_C* ap;
} Context;


#endif