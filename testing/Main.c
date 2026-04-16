#include "Context.h"

int process_args(int argc, char* argv[]){
    int ret;
    
    Context.ap = ArgParsing_C_get_instance();

    // Define table of arguments
    APTableEntry_C arg_table[] = {
        { .abbr_form="a", .full_form="algorithms", .initialized=false, .data_type=UNSIGNED_INT, .required=false , .default_value=true, .data.number_u64=0x3f  },
        { .abbr_form="t", .full_form="trace", .initialized=false, .data_type=FLAG, .required=false , .default_value=true, .data.flag=true  },
    };

    // Establish table of arguments
    ret = ArgParsing_C_set_arg_table(Context.ap, arg_table, sizeof(arg_table) / sizeof(APTableEntry_C));
    if(ret != 0){
        printf("ERROR: ArgParsing_C_set_arg_table() return code -> %d\n", ret);
        return -1;
    }
    
    ArgParsing_C_set_input_args(Context.ap, argc, argv);
    
    ret = ArgParsing_C_parse(Context.ap);
    if(ret != 0){
        printf("ERROR: ArgParsing_C_parse() return code -> %d\n", ret);
        return -1;
    }

    return 0;
}


int main(int argc, char* argv[]){
    int ret;

    // Clear the Context instance
    memset((void*)&Context, 0, sizeof(Context));

    // Process program arguments
    ret = process_args(argc, argv);
    if(ret != 0){
        return -1;
    }

    return 0;
}