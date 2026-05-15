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
    Testcase* tc;
    int ret;

    // Allocate and initialize Testcase object
    tc = Testcase_init(SHA224_ALG);
    if(tc == NULL){
        return -1;
    }

    // Perform the hashing operation
    sha224_chain(tc->s224, tc->bin_msg, tc->msg_bytelen);
    sha224_end(tc->s224);
    sha224_get_hash(tc->s224, tc->bin_res_hash);
    sha224_get_stringified_hash(tc->s224, tc->str_res_hash);
    
    // Validate results after execution
    ret = Testcase_validate(tc);
    if(ret != 0){
        return -1;
    }

    // If trace is enabled, create testcase report
    if(ctxt.trace){
        ret = Testcase_report(tc);
        if(ret != 0){
            return -1;
        }
    }

    // Deallocate Testcase object
    ret = Testcase_delete(tc);
    if(ret != 0){
        return -1;
    }

    return 0;
}