#ifndef MATH_MERSENNE_H_
#define MATH_MERSENNE_H_

#include <cstdio>
#include <cmath>
#include <iostream>

using namespace std;

class Mersenne {
    public:
        typedef unsigned __int128 uint128_t;

        static const uint32_t PRIME_EXP = 61;
        static const uint64_t PR = 2305843009213693951;

        static uint64_t modp(uint64_t);
        static uint64_t modp_128(uint128_t);
        static uint64_t neg(uint64_t);
        static uint64_t add(uint64_t, uint64_t);
        static uint64_t sub(uint64_t, uint64_t);
        static uint64_t mul(uint64_t, uint64_t);
        static uint64_t inverse(uint64_t a);
        static uint64_t inner_product(uint64_t*, uint64_t*, uint64_t);
        static uint64_t inner_product(uint64_t**, uint64_t**, uint64_t, uint64_t);
        static uint64_t inner_product(uint64_t*, vector<uint64_t>, uint64_t);
        static uint64_t inner_product(uint64_t**, uint64_t*, uint64_t, uint64_t);
        static uint64_t randomize(PRNG& G);
        static uint64_t batch_sum(uint64_t*, uint64_t);
        static uint64_t batch_add(uint64_t*, uint64_t*, uint64_t);
};

inline uint64_t Mersenne::modp(uint64_t a) {
    uint64_t res = (a>>PRIME_EXP) + (a & PR);
    if (res >= PR) {
        res -= PR;
    }
    return res;
}

inline uint64_t Mersenne::modp_128(uint128_t a){
    uint64_t higher, middle, lower;
    higher = (a >> (2 * PRIME_EXP));
    middle = (a >> PRIME_EXP) & PR;
    lower = a & PR;
    return modp(higher + middle + lower);
}

inline uint64_t Mersenne::neg(uint64_t a) {
    // assert(a < PR);
    if (a > 0) {
        return PR - a;
    } else {
        return 0;
    }
}

inline uint64_t Mersenne::add(uint64_t a, uint64_t b) {
    uint64_t res = a + b;
    if (res >= PR) {
        res -= PR;
    }
    return res;
}

inline uint64_t Mersenne::sub(uint64_t a, uint64_t b) {
    if (a >= b) {
        return a - b;
    } else {
        return PR - b + a;
    }
}

inline uint64_t Mersenne::mul(uint64_t a, uint64_t b) {
    uint128_t res = ((uint128_t) a) * ((uint128_t) b);
    uint64_t higher = (res>>PRIME_EXP);
    uint64_t lower = res & PR;
    return add(higher, lower);
}

inline uint64_t Mersenne::inverse(uint64_t a) {
    uint64_t left = a;
    uint64_t right = PR;
    uint64_t x = 1, y = 0, u = 0, v = 1;
    // uint64_t gcd = a;
    uint64_t w, z;
    while(left != 0) {
        w = right / left;
        z = right % left;
        right = left;
        left = z;

        z = u - w * x;
        u = x;
        x = z;

        z = v - w * y;
        v = y;
        y = z;
    }
    if (u >= PR) {
        u += PR;
    }
    return u;
}

inline uint64_t Mersenne::batch_add(uint64_t* a, uint64_t* b, uint64_t size) {
    uint128_t result = 0;
    uint64_t bound = 63;
    uint64_t start, end;
    start = 0;
    while(true) {
        if (start + bound < size) {
            end = start + bound;
        }
        else {
            end = size;
        }
        for(uint64_t i = start; i < end; i++) {
            result += ((uint128_t)a[i]) + ((uint128_t)b[i]);
        }
        result = modp_128(result);
        start = end;
        if (start == size) break;
    }
    return result;
}

inline uint64_t Mersenne::batch_sum(uint64_t* a, uint64_t size) {
    uint128_t result = 0;
    uint64_t bound = 63;
    uint64_t start, end;
    start = 0;
    while(true) {
        if (start + bound < size) {
            end = start + bound;
        }
        else {
            end = size;
        }
        for(uint64_t i = start; i < end; i++) {
            result += (uint128_t)a[i];
        }
        result = modp_128(result);
        start = end;
        if (start == size) break;
    }
    return result;
}

inline uint64_t Mersenne::inner_product(uint64_t* a, uint64_t* b, uint64_t size) {
    uint128_t result = 0;
    uint64_t bound = 63;
    uint64_t start, end;
    start = 0;
    while(true) {
        if (start + bound < size) {
            end = start + bound;
        }
        else {
            end = size;
        }
        for(uint64_t i = start; i < end; i++) {
            result += ((uint128_t)a[i]) * ((uint128_t)b[i]);
        }
        result = modp_128(result);
        start = end;
        if (start == size) break;
    }
    return result;
}

inline uint64_t Mersenne::inner_product(uint64_t* a, vector<uint64_t> b, uint64_t size) {
    uint128_t result = 0;
    uint64_t bound = 63;
    uint64_t start, end;
    start = 0;
    while(true) {
        if (start + bound < size) {
            end = start + bound;
        }
        else {
            end = size;
        }
        for(uint64_t i = start; i < end; i++) {
            result += ((uint128_t)a[i]) * ((uint128_t)b[i]);
        }
        result = modp_128(result);
        start = end;
        if (start == size) break;
    }
    return result;
}


inline uint64_t Mersenne::inner_product(uint64_t** a, uint64_t* b, uint64_t rows, uint64_t cols) {
    uint128_t result = 0;
    uint64_t bound = 63;
    uint64_t size = cols;

    uint64_t start, end;
    for(uint64_t row = 0; row < rows; row++) {
        start = 0;
        while(true) {
            if (start + bound < size) {
                end = start + bound;
            }
            else {
                end = size;
            }
            for(uint64_t i = start; i < end; i++) {
                result += ((uint128_t)a[row][i]) * ((uint128_t)b[i]);
            }
            result = modp_128(result);
            start = end;
            if (start == size) break;
        }
    }
    return result;
}

inline uint64_t Mersenne::randomize(PRNG& G) {
    uint64_t r = G.get_word();
    return r & PR;
}

#endif