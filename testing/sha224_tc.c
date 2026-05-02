#include "Context.h"


int sha224_tc(){
    size_t idx;

    idx = Randomizer_C_gen_integral_range(ctxt.rnd, 0, N_SHA224_TVS);

    printf("idx=%ld\n", idx);
    printf("seed=%d\n", ctxt.seed);

    return 0;
}