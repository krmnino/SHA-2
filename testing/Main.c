/*
MIT License

Copyright (c) 2026 Kurt Manrique-Nino

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


#include "Context.h"


int process_args(int argc, char* argv[]){
    int ret;
    
    Context.ap = ArgParsing_C_get_instance();

    // Define table of arguments
    APTableEntry_C arg_table[] = {
        { .abbr_form="a", .full_form="algorithms", .initialized=false, .data_type=UNSIGNED_INT, .required=false, .default_value=true , .data.number_u64=DEFAULT_ALGORITHMS_ARGVAL  },
        { .abbr_form="s", .full_form="seed"      , .initialized=false, .data_type=UNSIGNED_INT, .required=true , .default_value=false, .data={0}  },
        { .abbr_form="n", .full_form="n_tests"   , .initialized=false, .data_type=UNSIGNED_INT, .required=true , .default_value=false, .data={0}  },
        { .abbr_form="t", .full_form="trace"     , .initialized=false, .data_type=FLAG        , .required=false, .default_value=false, .data.flag=true  },
    };

    // Establish table of arguments, argc, and argv
    ret = ArgParsing_C_set_arg_table(Context.ap, arg_table, sizeof(arg_table) / sizeof(APTableEntry_C));
    if(ret != 0){
        printf("ERROR: ArgParsing_C_set_arg_table() return code -> %d\n", ret);
        return -1;
    }
    ArgParsing_C_set_input_args(Context.ap, argc, argv);
    
    // Parse the program arguments
    ret = ArgParsing_C_parse(Context.ap);
    if(ret != 0){
        printf("ERROR: ArgParsing_C_parse() return code -> %d\n", ret);
        return -1;
    }

    // Obtain argument values, perform additional validation, and then save them into the Context structure
    Context.algorithms = ArgParsing_C_get_value_UNSIGNED_INT(Context.ap, "algorithms", false);
    if((Context.algorithms & (~(uint64_t)DEFAULT_ALGORITHMS_ARGVAL)) != 0 || Context.algorithms == 0x0){
        printf("ERROR: -a/--algorithm argument value should not exceed %x.\n", DEFAULT_ALGORITHMS_ARGVAL);
        printf("The following values represent SHA-2 algorithms and can be bit-wise OR'd:\n");
        printf(" SHA-224     = 0x01\n");
        printf(" SHA-256     = 0x02\n");
        printf(" SHA-384     = 0x04\n");
        printf(" SHA-512     = 0x08\n");
        printf(" SHA-512/224 = 0x10\n");
        printf(" SHA-512/256 = 0x20\n");
        return -1;
    }
    Context.seed = (uint32_t)ArgParsing_C_get_value_UNSIGNED_INT(Context.ap, "seed", false);
    if(Context.seed == 0){
        printf("ERROR: seed value cannot be zero.\n");
    }
    Context.n_tests = ArgParsing_C_get_value_UNSIGNED_INT(Context.ap, "n_tests", false);
    if(Context.n_tests == 0){
        Context.infinite_loop = true;
    }
    Context.trace = ArgParsing_C_get_value_FLAG(Context.ap, "trace", false);
    return 0;
}


int main(int argc, char* argv[]){
    int ret;
    uint64_t shifter;
    SHA_Algs picked_alg;

    // Clear the Context instance
    memset((void*)&Context, 0, sizeof(Context));

    // Process program arguments
    ret = process_args(argc, argv);
    if(ret != 0){
        return -1;
    }

    // Initialize Randomizer
    Context.rnd = Randomizer_C_init(Context.seed);

    // Main loop
    for(size_t i = 0; i < Context.n_tests; i++){
        // Pick an allowed algorithm
        while(true){
            shifter = Randomizer_C_gen_integral_range(Context.rnd, 0, (NUM_ALGORITHMS - 1));
            picked_alg = Context.algorithms & (1 << shifter);
            if(picked_alg != 0){
                break;
            }
        }
        switch(picked_alg){
        case SHA224_ALG:
            printf(">> %ld - picked SHA224\n", i);
            break;
        case SHA256_ALG:
            printf(">> %ld - picked SHA256\n", i);
            break;
        case SHA384_ALG:
            printf(">> %ld - picked SHA384\n", i);
            break;
        case SHA512_ALG:
            printf(">> %ld - picked SHA512\n", i);
            break;
        case SHA512_224_ALG:
            printf(">> %ld - picked SHA512/224\n", i);
            break;
        case SHA512_256_ALG:
            printf(">> %ld - picked SHA512/256\n", i);
            break;
        default:
            break;
        }
        Randomizer_C_root_seed_next(Context.rnd);
    }

    return 0;
}