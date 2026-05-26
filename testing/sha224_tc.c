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


int sha224_tc(){
    uint8_t* curr_bin_msg;
    size_t remaining;
    uint32_t picked_len;
    int ret;

    // Intialize SHA-224 object
    ctxt.tc->s224 = sha224_init();
    if(ctxt.tc->s224 == NULL){
        ctxt.tc->errors = ctxt.tc->errors | SHA2_INIT_FAIL;
        return -1;
    }

    // Only for messages of length non-zero
    if(ctxt.tc->msg_bytelen != 0){
        // Allocate and populate array of message sections sizes
        ctxt.tc->sub_bin_msg_sizes = (uint32_t*)calloc(ctxt.tc->msg_bytelen, sizeof(uint32_t));
        remaining = ctxt.tc->msg_bytelen;
        ctxt.tc->sub_bin_msg_idx = 0;
        while(remaining != 0){
            picked_len = Randomizer_C_gen_integral_range(ctxt.rnd, 1, remaining);
            ctxt.tc->sub_bin_msg_sizes[ctxt.tc->sub_bin_msg_idx] = picked_len;
            ctxt.tc->sub_bin_msg_idx++;
            remaining -= picked_len;
        }
        Randomizer_C_shuffle(ctxt.rnd, (void*)ctxt.tc->sub_bin_msg_sizes, ctxt.tc->sub_bin_msg_idx, sizeof(uint32_t));

        // Provide sections of message to hashing function
        curr_bin_msg = ctxt.tc->bin_msg;
        for(size_t i = 0; i < ctxt.tc->sub_bin_msg_idx; i++){
            ret = sha224_chain(ctxt.tc->s224, curr_bin_msg, ctxt.tc->sub_bin_msg_sizes[i]);
            if(ret != 0){
                ctxt.tc->errors = ctxt.tc->errors | SHA2_CHAIN_FAIL;
            }
            curr_bin_msg += ctxt.tc->sub_bin_msg_sizes[i];
        }
    }
    else{
        // Perform the hashing operation
        ret = sha224_chain(ctxt.tc->s224, ctxt.tc->bin_msg, ctxt.tc->msg_bytelen);
        if(ret != 0){
            ctxt.tc->errors = ctxt.tc->errors | SHA2_CHAIN_FAIL;
        }
    }

    // Wrap up hashing of the message
    ret = sha224_end(ctxt.tc->s224);
    if(ret != 0){
        ctxt.tc->errors = ctxt.tc->errors | SHA2_END_FAIL;
    }
    ret = sha224_get_hash(ctxt.tc->s224, ctxt.tc->bin_res_hash);
    if(ret != 0){
        ctxt.tc->errors = ctxt.tc->errors | SHA2_GET_HASH_FAIL;
    }
    ret = sha224_get_stringified_hash(ctxt.tc->s224, ctxt.tc->str_res_hash);
    if(ret != 0){
        ctxt.tc->errors = ctxt.tc->errors | SHA2_GET_STRINGIFIED_HASH_FAIL;
    }
    ret = sha224_delete(ctxt.tc->s224);
    if(ret != 0){
        ctxt.tc->errors = ctxt.tc->errors | SHA2_DELETE_FAIL;
    }
    
    // Validate results after execution
    ret = Testcase_validate(ctxt.tc);
    if(ret != 0){
        return -1;
    }

    // If trace is enabled, create testcase report
    if(ctxt.trace){
        ret = Testcase_report(ctxt.tc);
        if(ret != 0){
            return -1;
        }
    }
    return 0;
}