#ifndef PROTOCOLS_BINSRYCHECK_HPP_
#define PROTOCOLS_BINSRYCHECK_HPP_

#include "BinaryCheck.h"

#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include <cstdlib>
#include <ctime>


uint64_t get_rand() {
    uint64_t left, right;
    left = rand();
    right = ((uint64_t)rand()) + (left<<32);
    return right & Mersenne::PR;
}

void get_bases(uint64_t n, uint64_t** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j] = 1;
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    uint64_t denominator, numerator;
                    if (j > l) {
                        denominator = j - l;
                    }
                    else {
                        denominator = Mersenne::neg(l - j);
                    }
                    numerator = i + n - l;
                    result[i][j] = Mersenne::mul(result[i][j], Mersenne::mul(Mersenne::inverse(denominator), numerator));
                }
            }
        }
    }
}

void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result) {

    for(uint64_t i = 0; i < n; i++) {
        result[i] = 1;
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                uint64_t denominator, numerator; 
                if (i > j) { 
                    denominator = i - j;
                } 
                else { 
                    denominator = Mersenne::neg(j - i);
                }
                if (r > j) { 
                    numerator = r - j; 
                } 
                else { 
                    numerator = Mersenne::neg(j - r);
                }
                result[i] = Mersenne::mul(result[i], Mersenne::mul(Mersenne::inverse(denominator), numerator));
            }
        }
    }
}

void append_one_msg(LocalHash &hash, uint64_t msg) {
    hash.update(msg);
}

void append_msges(LocalHash &hash, vector<uint64_t> msges) {
    for(uint64_t msg: msges) {
        hash.update(msg);
    }
}

uint64_t get_challenge(LocalHash &hash) {
    
    

    uint64_t r = hash.final();
    return r & Mersenne::PR;
}

DZKProof prove(
    uint64_t** input_left, 
    uint64_t** input_right, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks
) {

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    LocalHash transcript_hash;

    s *= 4;
    vector<vector<uint64_t>> p_evals_masked;

    uint64_t** base = new uint64_t*[k - 1];
    for (uint64_t i = 0; i < k - 1; i++) {
        base[i] = new uint64_t[k];
    }

    get_bases(k, base);

    uint64_t* eval_base = new uint64_t[k];
    uint64_t s0;
    uint64_t** eval_result = new uint64_t*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = new uint64_t[k];
    }
    uint64_t* eval_p_poly = new uint64_t[2 * k - 1];  
    uint128_t temp_result;
    uint64_t index;
    uint16_t cnt = 0;
    
    
    while(true){

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

        for(uint64_t i = 0; i < k; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(uint64_t i = 0; i < k - 1; i++) {
            eval_p_poly[i + k] = 0;
            for(uint64_t j = 0; j < k; j++) {
                for (uint64_t l = 0; l < k; l++) {
                    eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }    

        vector<uint64_t> ss(2 * k - 1);       
        for(uint64_t i = 0; i < 2 * k - 1; i++) {           
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
        }

        uint64_t sum = 0;
        for(uint64_t j = 0; j < k; j++) {
            sum += eval_p_poly[j];
        }
        sum = Mersenne::modp(sum);

        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        append_msges(transcript_hash, ss);
        uint64_t r = get_challenge(transcript_hash);

        evaluate_bases(k, r, eval_base);

        s0 = s;
        s = (s - 1) / k + 1;
       
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
               
                if (index < s0) {
                    
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }

                    input_left[i][j] = Mersenne::modp_128(temp_result);
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_right[l][index]);
                    }
                   

                    input_right[i][j] = Mersenne::modp_128(temp_result);
                   
                }
                else {
                    input_left[i][j] = 0;
                   
                    input_right[i][j] = 0;
                }
               

            }
        }
        cnt++;
    }

   

    for(uint64_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;

    for (uint64_t i = 0; i < k - 1; i++) {
        delete[] base[i];
    }
    delete[] base;
    delete[] eval_base;

    DZKProof proof = { 
        p_evals_masked,
    };
    return proof;
}


VerMsg gen_vermsg(
    DZKProof proof, 
    uint64_t** input,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
   
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    LocalHash transcript_hash;

    uint64_t* eval_base = new uint64_t[k];
    uint64_t* eval_base_2k = new uint64_t[2 * k - 1];
    uint64_t r, s0, index, cnt = 0;
    uint128_t temp_result;

    uint64_t len = log(4 * T) / log(k) + 1;

    vector<uint64_t> p_eval_ksum_ss(len);
    vector<uint64_t> p_eval_r_ss(len);
    uint64_t final_input;
    uint64_t final_result_ss;
    s *= 4;
    while(true)
    {
        append_msges(transcript_hash, proof.p_evals_masked[cnt]);

        if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
               
            } 
        } else {
            
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        
        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) { 
            res += proof.p_evals_masked[cnt][j];
        }
        p_eval_ksum_ss[cnt] = Mersenne::modp(res);

        if(s == 1) {
            r = get_challenge(transcript_hash);
            
            assert(r < Mersenne::PR);
            
            evaluate_bases(k, r, eval_base);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }
            final_input = Mersenne::modp_128(temp_result);

           

            evaluate_bases(2 * k - 1, r, eval_base_2k);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
            }
            final_result_ss = Mersenne::modp_128(temp_result);
            break;
        }


        r = get_challenge(transcript_hash);

        evaluate_bases(2 * k - 1, r, eval_base_2k);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
        }
        p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);

       

        evaluate_bases(k, r, eval_base);
        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input[l][index]);
                    }
                    input[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input[i][j] = 0;
                }
            }
        }
 
        cnt++;
    }

    delete[] eval_base;
    delete[] eval_base_2k;

    VerMsg vermsg(
        p_eval_ksum_ss,
        p_eval_r_ss,
        final_input,
        final_result_ss
    );
    return vermsg;
}

bool _verify(
    DZKProof proof, 
    uint64_t** input, 
    VerMsg other_vermsg, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t len = log(4 * T) / log(k) + 1;
    
    VerMsg self_vermsg = gen_vermsg(proof, input, batch_size, k, masks_ss, prover_ID, party_ID);
    
    uint64_t p_eval_ksum, p_eval_r;
    uint64_t first_output = Mersenne::mul(Mersenne::neg(Mersenne::inverse(2)), batch_size);

    p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[0], other_vermsg.p_eval_ksum_ss[0]);
    
    if(p_eval_ksum != first_output) {  
        return false;
    }

    for(uint64_t i = 1; i < len; i++) {
        p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[i], other_vermsg.p_eval_ksum_ss[i]);
        p_eval_r = Mersenne::add(self_vermsg.p_eval_r_ss[i - 1], other_vermsg.p_eval_r_ss[i - 1]);
        
        if(p_eval_ksum != p_eval_r) {     
            return false;
        }
    }
    uint64_t res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {      
        return false;
    } 
    return true;
}

#endif

