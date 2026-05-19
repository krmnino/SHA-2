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


#include "SHA2Testing.h"


volatile sig_atomic_t running = true;
Context ctxt = { 0 };

int process_args(int argc, char* argv[]){
    int ret;
    
    ctxt.ap = ArgParsing_C_get_instance();

    // Define table of arguments
    APTableEntry_C arg_table[] = {
        { .abbr_form="a", .full_form="algorithms"   , .initialized=false, .data_type=UNSIGNED_INT, .required=false, .default_value=true , .data.number_u64=DEFAULT_ALGORITHMS_ARGVAL  },
        { .abbr_form="s", .full_form="seed"         , .initialized=false, .data_type=UNSIGNED_INT, .required=true , .default_value=false, .data={0}  },
        { .abbr_form="n", .full_form="max_testcases", .initialized=false, .data_type=UNSIGNED_INT, .required=true , .default_value=false, .data={0}  },
        { .abbr_form="e", .full_form="max_errors"   , .initialized=false, .data_type=UNSIGNED_INT, .required=true , .default_value=true , .data.number_u64=5  },
        { .abbr_form="t", .full_form="trace"        , .initialized=false, .data_type=FLAG        , .required=false, .default_value=false, .data.flag=true  },
    };

    // Establish table of arguments, argc, and argv
    ret = ArgParsing_C_set_arg_table(ctxt.ap, arg_table, sizeof(arg_table) / sizeof(APTableEntry_C));
    if(ret != 0){
        printf("ERROR: ArgParsing_C_set_arg_table() return code -> %d\n", ret);
        return -1;
    }
    ArgParsing_C_set_input_args(ctxt.ap, argc, argv);
    
    // Parse the program arguments
    ret = ArgParsing_C_parse(ctxt.ap);
    if(ret != 0){
        printf("ERROR: ArgParsing_C_parse() return code -> %d\n", ret);
        return -1;
    }

    // Obtain argument values, perform additional validation, and then save them into the ctxt structure
    ctxt.algorithms = ArgParsing_C_get_value_UNSIGNED_INT(ctxt.ap, "algorithms", false);
    if((ctxt.algorithms & (~(uint64_t)DEFAULT_ALGORITHMS_ARGVAL)) != 0 || ctxt.algorithms == 0x0){
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
    ctxt.init_seed = (uint32_t)ArgParsing_C_get_value_UNSIGNED_INT(ctxt.ap, "seed", false);
    if(ctxt.init_seed == 0){
        printf("ERROR: seed value cannot be zero.\n");
    }
    ctxt.max_testcases = ArgParsing_C_get_value_UNSIGNED_INT(ctxt.ap, "max_testcases", false);
    if(ctxt.max_testcases == 0){
        ctxt.infinite_loop = true;
    }
    ctxt.max_errors = ArgParsing_C_get_value_UNSIGNED_INT(ctxt.ap, "max_errors", false);
    ctxt.trace = ArgParsing_C_get_value_FLAG(ctxt.ap, "trace", false);
    return 0;
}


void terminating_handler(int s){
    running = false;
}


int main(int argc, char* argv[]){
    struct sigaction sa_struct;
    Testcase* curr;
    Testcase* next;
    uint64_t shifter;
    SHA_Algs picked_alg;
    int ret;

    // Clear the ctxt instance
    memset((void*)&ctxt, 0, sizeof(ctxt));

    // Process program arguments
    ret = process_args(argc, argv);
    if(ret != 0){
        return -1;
    }

    // Initialize Randomizer
    ctxt.rnd = Randomizer_C_init(ctxt.init_seed);

    // Set up signal handler to stop program
    sa_struct.sa_handler = terminating_handler;
    sigemptyset(&sa_struct.sa_mask);
    sa_struct.sa_flags = 0;
    sigaction(SIGINT, &sa_struct, NULL);

    // Main loop
    for(ctxt.testcase_counter = 0; 
        (ctxt.testcase_counter < ctxt.max_testcases || ctxt.infinite_loop) && ctxt.error_counter < ctxt.max_errors && running;
        ctxt.testcase_counter++){
        // Pick an allowed algorithm
        while(true){
            shifter = Randomizer_C_gen_integral_range(ctxt.rnd, 0, (NUM_ALGORITHMS - 1));
            picked_alg = ctxt.algorithms & (1 << shifter);
            if(picked_alg != 0){
                break;
            }
        }

        // Allocate and initialize Testcase object for picked algorithm
        ctxt.tc = Testcase_init(picked_alg);
        if(ctxt.tc == NULL){
            return -1;
        }

        // Branch to the appropiate testcase function
        switch(picked_alg){
        case SHA224_ALG:
            sha224_tc();
            break;
        case SHA256_ALG:
            sha256_tc();
            break;
        case SHA384_ALG:
            sha384_tc();
            break;
        case SHA512_ALG:
            sha512_tc();
            break;
        case SHA512_224_ALG:
            break;
        case SHA512_256_ALG:
            break;
        default:
            break;
        }

        // Check if current Testcase encountered an error
        if(ctxt.tc->errors != NO_ERROR){
            if(ctxt.error_tcs_head == NULL){
                ctxt.error_tcs_head = ctxt.tc;
                ctxt.error_tcs_curr = ctxt.error_tcs_head;
            }
            else{
                ctxt.error_tcs_curr->next = ctxt.tc;
                ctxt.error_tcs_curr = ctxt.tc;
            }
            ctxt.error_counter++;
        }
        else{
            // Deallocate Testcase object
            ret = Testcase_delete(ctxt.tc);
            if(ret != 0){
                return -1;
            }
        }

        // Next seed
        Randomizer_C_root_seed_next(ctxt.rnd);
    }

    // If there are any errors, loop though them and free the Testcase objects
    printf("======================= END OF RUN REPORT =======================\n");
    printf("Number of tests  : %ld\n", ctxt.testcase_counter);
    printf("Number of errors : %ld\n", ctxt.error_counter);
    if(ctxt.error_counter != 0){
        curr = ctxt.error_tcs_head;
        while(curr != NULL){
            Testcase_report(curr);
            next = curr->next;
            Testcase_delete(curr);
            curr = next;
        }
    }

    // Deallocate Randomizer
    Randomizer_C_delete(ctxt.rnd);

    return 0;
}