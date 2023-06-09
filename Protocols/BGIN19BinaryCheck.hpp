#ifndef PROTOCOLS_BGIN19BINARYCHECK_HPP_
#define PROTOCOLS_BGIN19BINARYCHECK_HPP_

#include "BGIN19BinaryCheck.h"

#include "Math/gf2n.h"
#include <cstdlib>
#include <ctime>
#include <chrono>

template <class _T>
BGIN19DZKProof BGIN19Protocol<_T>::_prove(
    size_t node_id,
    BGIN19Field** masks,
    size_t batch_size, 
    BGIN19Field sid,
    PRNG prng
) {
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;

    // Vectors of masked evaluations of polynomial p(X)
    vector<vector<BGIN19Field>> p_evals_masked;
    size_t k_max = k > k2 ? k : k2;

    // Evaluations of polynomial p(X)
    BGIN19Field* eval_p_poly = new BGIN19Field[2 * k_max - 1];  

    BGIN19Field** base = new BGIN19Field*[k_max - 1];
    for (size_t i = 0; i < k_max - 1; i++) {
        base[i] = new BGIN19Field[k_max];
    }
    
    BGIN19Field** eval_result = new BGIN19Field*[k_max];
    for(size_t i = 0; i < k_max; i++) {
        eval_result[i] = new BGIN19Field[k_max];
        for (size_t j = 0; j < k_max; j++) {
            eval_result[i][j] = 0;
        }
    }

    BGIN19Field* eval_base = new BGIN19Field[k_max];

    // ===============================  First Round  ===============================

    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now();
    #endif

    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;

    // Transcript
    BGIN19LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    
    BGIN19ShareTupleBlock k_share_tuple_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    
    size_t cur_k_blocks = 0;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;

    size_t padded_s = block_cols_num * BLOCK_SIZE;

    // bs = 6400, s = 800 -> 832
    s = padded_s;

    BGIN19Field* thetas = new BGIN19Field[s];
    for(size_t j = 0; j < s; j++) {
        thetas[j].randomize(prng);
    }

    for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {

        // fetch k tuple_blocks
        if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
            for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
        }
        else {
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
        }
        
        for(size_t i = 0; i < k; i++) { 
            BGIN19ShareTupleBlock row_tuple_block = k_share_tuple_blocks[i];
            
            for(size_t j = 0; j < k; j++) {  
                BGIN19ShareTupleBlock col_tuple_block = k_share_tuple_blocks[j];

                // x_i * y_{i-1} + y_i * x_{i-1}
                long this_value_block = (row_tuple_block.input1.first & col_tuple_block.input2.second) ^ (row_tuple_block.input2.first & col_tuple_block.input1.second);

                for(size_t l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_value_block >> l) & (uint64_t)1) {
                        eval_result[i][j] += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
        }
        cur_k_blocks += k;
    }

    for(size_t i = 0; i < k; i++) {
        eval_p_poly[i] = eval_result[i][i];
    }

    BGIN19Lagrange::get_bases(k, base);

    for(size_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(size_t j = 0; j < k; j++) {
            for (size_t l = 0; l < k; l++) {
                eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
            }
        }
    }

    #ifdef TIMING
        auto end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute p coeffs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    size_t cnt = 0;

    vector<BGIN19Field> ss(2 * k - 1);       
    for(size_t i = 0; i < 2 * k - 1; i++) {           
        ss[i] = eval_p_poly[i] - masks[cnt][i];
    }
    p_evals_masked.push_back(ss);


    // ===============================  Following Rounds  ===============================

    transcript_hash.append_msges(ss);
    BGIN19Field r = transcript_hash.get_challenge();

    cnt++;

    BGIN19Lagrange::evaluate_bases(k, r, eval_base);

    s *= 2;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
 
    BGIN19Field **input_left, **input_right;
    input_left = new BGIN19Field*[k2];
    input_right = new BGIN19Field*[k2];

    for(size_t i = 0; i < k2; i++) {
        input_left[i] = new BGIN19Field[s];
        input_right[i] = new BGIN19Field[s];
    }

    size_t index = 0;
    cur_k_blocks = 0;

    uint64_t table_size = 1 << k;
    BGIN19Field* input_table = new BGIN19Field[table_size];

    for (uint64_t i = 0; i < table_size; i++) {
        BGIN19Field sum = 0;
        for (uint64_t j = 0; j < k; j++) {
            if ((i >> j) & 1)
                sum += eval_base[j];
        }
        input_table[i] = sum;
    }

    long* bit_blocks_left1 = new long[k];
    long* bit_blocks_left2 = new long[k];
    long* bit_blocks_right1 = new long[k];
    long* bit_blocks_right2 = new long[k];

    int bits_num = k2;
    int group_num = BLOCK_SIZE / k2;

    for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {

        // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
        if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
            for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
        }
        else {
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
        }

        for (uint64_t i = 0; i < k; i++) {

            BGIN19ShareTupleBlock cur_block = k_share_tuple_blocks[i];

            bit_blocks_left1[i] = cur_block.input1.first;
            bit_blocks_left2[i] = cur_block.input2.first;

            bit_blocks_right1[i] = cur_block.input2.second;
            bit_blocks_right2[i] = cur_block.input1.second;
        }

        // k = 8, bits_num = 8, group_num = 8
        // bit_id = 0, 1, 2, ..., 7
        for (int bit_id = 0; bit_id < bits_num; bit_id++) {
            // group_id = 0, 1, 2, ..., 7
            for (int group_id = 0; group_id < group_num; group_id++) {

                // bit_id = 0:  overall_bit_id = 0, 8, 16, 24, 32, 40, 48, 56
                // bit_id = 1:  overall_bit_id = 1, 9, 17, 25, 33, 41, 49, 57
                // ......
                // bit_id = 7:  overall_bit_id = 7, 15, 23, 31, 39, 47, 49, 63
                int overall_bit_id = group_id * bits_num + bit_id;
                int cur_index = index + overall_bit_id * 2;
                int row = cur_index / s;
                int col = cur_index % s;

                if (index >= s0) {
                    if ((uint64_t)row == k2) {
                        break;
                    }
                    else {
                        input_left[row][col] = input_left[row][col + 1] = 0;
                        input_right[row][col] = input_right[row][col + 1] = 0;
                        continue;
                    }
                }

                uint64_t left_id1 = 0, left_id2 = 0, right_id1 = 0, right_id2 = 0;

                for (int j = 0; j < bits_num; j++) {
                    left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                    left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                    right_id2 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                }

                input_left[row][col] = input_table[left_id1 & 0xc] * thetas[block_col * BLOCK_SIZE + overall_bit_id];
                input_left[row][col + 1] = input_table[left_id2 & 0xc] * thetas[block_col * BLOCK_SIZE + overall_bit_id];
                input_right[row][col] = input_table[right_id1 & 0xc];
                input_right[row][col + 1] = input_table[right_id2 & 0xc];
            } 
        }
        
        index += BLOCK_SIZE * 2;
        cur_k_blocks += k;
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    BGIN19Lagrange::get_bases(k2, base);

    while(true){

        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < k2; j++) {
                eval_result[i][j] = inner_product(input_left[i], input_right[j], s);
            }
        }

        for(size_t i = 0; i < k2; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(size_t i = 0; i < k2 - 1; i++) {
            eval_p_poly[i + k2] = 0;
            for(size_t j = 0; j < k2; j++) {
                for (size_t l = 0; l < k2; l++) {
                    eval_p_poly[i + k2] += base[i][j] * eval_result[j][l] * base[i][l];
                }
            }
        }

        vector<BGIN19Field> ss(2 * k2 - 1);       
        for (size_t i = 0; i < 2 * k2 - 1; i++) {           
            ss[i] = eval_p_poly[i] - masks[cnt][i];
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        transcript_hash.append_msges(ss);
        r = transcript_hash.get_challenge();

        BGIN19Lagrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;
       
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < s; j++) {
                index = i * s + j;
               
                if (index < s0) {
                    BGIN19Field temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += eval_base[l] * input_left[l][index];
                    }
                    input_left[i][j] = temp_result;

                    temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += eval_base[l] * input_right[l][index];
                    }
                    input_right[i][j] = temp_result;
                }
                else {
                    input_left[i][j] = 0;
                    input_right[i][j] = 0;
                }
            }
        }

        cnt++;
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    #endif

    for(size_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;

    for (size_t i = 0; i < k - 1; i++) {
        delete[] base[i];
    }
    delete[] base;
    delete[] eval_base;

    for(size_t i = 0; i < k; i++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (size_t j = 0; j < cnt; j ++) {
        delete[] masks[j];
    }
    delete[] masks;

    BGIN19DZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

template <class _T>
BGIN19VerMsg BGIN19Protocol<_T>::_gen_vermsg(
    BGIN19DZKProof proof, 
    size_t node_id,
    BGIN19Field** masks_ss,
    size_t batch_size, 
    BGIN19Field sid,
    size_t prover_ID,
    size_t party_ID,
    PRNG prng
) {
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;

    size_t k_max = k > k2 ? k : k2;

    BGIN19Field* eval_base = new BGIN19Field[k_max];
    BGIN19Field* eval_base_2k = new BGIN19Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================
    
    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now();
    #endif

    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(2 * s) / log(k2) + 2;

    vector<BGIN19Field> b_ss(len);
    BGIN19Field final_input = 0, final_result_ss = 0;

    // Transcript
    BGIN19LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);

    size_t cnt = 0;
    BGIN19Field out_ss = 0, sum_ss = 0;

    transcript_hash.append_msges(proof.p_evals_masked[cnt]);
    BGIN19Field r = transcript_hash.get_challenge();
    
    // recover proof
    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;

    if (prev_party) {
        for (size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] += masks_ss[cnt][i];
        } 
    } else {
        for (size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }

    // sample randomness betas
    BGIN19Field* betas = new BGIN19Field[k];
    for(size_t j = 0; j < k; j++) {
        betas[j] = 1; //.randomize(prng);
    }

    // compute random linear combination on the first k outputs using betas
    for(size_t j = 0; j < k; j++) { 
        sum_ss = inner_product(betas, proof.p_evals_masked[cnt], k);
    }

    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    size_t cur_k_blocks = 0;
    BGIN19ShareTupleBlock k_share_tuple_blocks[k];

    size_t padded_s = block_cols_num * BLOCK_SIZE;

    s = padded_s;

    BGIN19Field* thetas = new BGIN19Field[s];
    for(size_t j = 0; j < s; j++) {
        thetas[j].randomize(prng);
    }

    if (prev_party) {
        for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {
            if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
                for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                    k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
            }
            else {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
            }

            for (size_t i = 0; i < k; i++) { 

                long this_block_value = k_share_tuple_blocks[i].rho.first;
                for(size_t l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_block_value >> l) & (uint64_t)1) {
                        out_ss += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
            cur_k_blocks += k;
        }
    }
    else {
        for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {
            if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
                for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                    k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
            }
            else {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
            }

            for (size_t i = 0; i < k; i++) { 
                long this_block_value = k_share_tuple_blocks[i].result.second ^ (k_share_tuple_blocks[i].input1.second & k_share_tuple_blocks[i].input2.second) ^ k_share_tuple_blocks[i].rho.second;
                for(size_t l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_block_value >> l) & (uint64_t)1) {
                        out_ss += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
            cur_k_blocks += k;
        }
    }
    
    b_ss[cnt] = sum_ss - out_ss;

    BGIN19Lagrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
    out_ss = inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

    #ifdef TIMING
        auto end = std::chrono::high_resolution_clock::now();
        cout << "First round (linearly combine output) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    // ===============================  Following Rounds  ===============================

    // new evaluations at random point r
    BGIN19Lagrange::evaluate_bases(k, r, eval_base);

    s *= 2;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
 
    BGIN19Field **input = new BGIN19Field*[k2];

    for(size_t i = 0; i < k2; i++) {
        input[i] = new BGIN19Field[s];
    }

    size_t index = 0;
    cur_k_blocks = 0;

    int bits_num = k2;
    int group_num = BLOCK_SIZE / k2;
    
    uint64_t table_size = 1 << k;
    BGIN19Field* input_table = new BGIN19Field[table_size];

    for (uint64_t i = 0; i < table_size; i++) {
        BGIN19Field sum = 0;
        for (uint64_t j = 0; j < k; j++) {
            if ((i >> j) & 1)
                sum += eval_base[j];
        }
        input_table[i] = sum;
    }

    if (prev_party) {

        long* bit_blocks_left1 = new long[k];
        long* bit_blocks_left2 = new long[k];

        for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {
            if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
                for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                    k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
            }
            else {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
            }

            for (uint64_t i = 0; i < k; i++) {

                BGIN19ShareTupleBlock cur_block = k_share_tuple_blocks[i];

                bit_blocks_left1[i] = cur_block.input1.first;
                bit_blocks_left2[i] = cur_block.input2.first;
            }

            // k = 8, bits_num = 8, group_num = 8
            // bit_id = 0, 1, 2, ..., 7
            for (int bit_id = 0; bit_id < bits_num; bit_id++) {
                // group_id = 0, 1, 2, ..., 7
                for (int group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 8, 16, 24, 32, 40, 48, 56
                    // bit_id = 1:  overall_bit_id = 1, 9, 17, 25, 33, 41, 49, 57
                    // ......
                    // bit_id = 7:  overall_bit_id = 7, 15, 23, 31, 39, 47, 49, 63
                    int overall_bit_id = group_id * bits_num + bit_id;
                    int cur_index = index + overall_bit_id * 2;
                    int row = cur_index / s;
                    int col = cur_index % s;

                    if (index >= s0) {
                        if ((uint64_t)row == k2) {
                            break;
                        }
                        else {
                            input[row][col] = input[row][col + 1] = 0;
                            continue;
                        }
                    }

                    uint64_t left_id1 = 0, left_id2 = 0;

                    for (int j = 0; j < bits_num; j++) {
                        left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                        left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    }

                    input[row][col] = input_table[left_id1 & 0xc] * thetas[block_col * BLOCK_SIZE + overall_bit_id];
                    input[row][col + 1] = input_table[left_id2 & 0xc] * thetas[block_col * BLOCK_SIZE + overall_bit_id];
                } 
            }
            
            index += BLOCK_SIZE * 2;
            cur_k_blocks += k;
        }
    } 
    else {
        long* bit_blocks_right1 = new long[k];
        long* bit_blocks_right2 = new long[k];

        for (size_t block_col = 0; block_col < block_cols_num; block_col ++) {

            if (block_col == block_cols_num - 1 && total_blocks_num - cur_k_blocks < k) {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * (total_blocks_num - cur_k_blocks));
                for (size_t i = total_blocks_num - cur_k_blocks; i < k; i++)
                    k_share_tuple_blocks[i] = BGIN19ShareTupleBlock();
            }
            else {
                memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(BGIN19ShareTupleBlock) * k);
            }

            // k = 8, bits_num = 8, group_num = 8
            // bit_id = 0, 1, 2, ..., 7
            for (int bit_id = 0; bit_id < bits_num; bit_id++) {
                // group_id = 0, 1, 2, ..., 7
                for (int group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 8, 16, 24, 32, 40, 48, 56
                    // bit_id = 1:  overall_bit_id = 1, 9, 17, 25, 33, 41, 49, 57
                    // ......
                    // bit_id = 7:  overall_bit_id = 7, 15, 23, 31, 39, 47, 49, 63
                    int overall_bit_id = group_id * bits_num + bit_id;
                    int cur_index = index + overall_bit_id * 2;
                    int row = cur_index / s;
                    int col = cur_index % s;

                    if (index >= s0) {
                        if ((uint64_t)row == k2) {
                            break;
                        }
                        else {
                            input[row][col] = input[row][col + 1] = 0;
                            continue;
                        }
                    }

                    uint64_t right_id1 = 0, right_id2 = 0;

                    for (int j = 0; j < bits_num; j++) {
                        right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                        right_id2 ^= ((bit_blocks_right2[j] >> overall_bit_id) << j);
                    }

                    input[row][col] = input_table[right_id1 & 0xc];
                    input[row][col + 1] = input_table[right_id2 & 0xc];
                } 
            }
            
            index += BLOCK_SIZE * 2;
            cur_k_blocks += k;
        }
    }

    cnt++;

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    while(true)
    {    
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if (prev_party) {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] += masks_ss[cnt][i];
            } 
        } else {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }

        sum_ss = 0;
        for (size_t j = 0; j < k2; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        b_ss[cnt] = sum_ss - out_ss;

        if (s == 1) {
            r = transcript_hash.get_challenge();

            BGIN19Lagrange::evaluate_bases(k2, r, eval_base);
            for(size_t i = 0; i < k2; i++) {
                final_input += eval_base[i] * input[i][0];
            }

            BGIN19Lagrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
            final_result_ss = inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

            break;
        }
        
        r = transcript_hash.get_challenge();

        BGIN19Lagrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
        out_ss = inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

        BGIN19Lagrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;

        for (size_t i = 0; i < k2; i++) {
            for (size_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    BGIN19Field temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += eval_base[l] * input[l][index];
                    }
                    input[i][j] = temp_result;
                }
                else {
                    input[i][j] = 0;
                }
            }
        }

        cnt++;
    }

#ifdef TIMING
    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
#endif


    delete[] eval_base;
    delete[] eval_base_2k;

    delete[] input;

    for (size_t j = 0; j < cnt; j ++) {
        delete[] masks_ss[j];
    }
    delete[] masks_ss;

    BGIN19VerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );

    return vermsg;
}

template <class _T>
bool BGIN19Protocol<_T>::_verify(
    BGIN19DZKProof proof, 
    BGIN19VerMsg other_vermsg, 
    size_t node_id,
    BGIN19Field** masks_ss,
    size_t batch_size, 
    BGIN19Field sid,
    size_t prover_ID,
    size_t party_ID,
    PRNG prng
) {
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;
    
    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(2 * s) / log(k2) + 2;
    
    BGIN19VerMsg self_vermsg = _gen_vermsg(proof, node_id, masks_ss, batch_size, sid, prover_ID, party_ID, prng);

    BGIN19Field b;

    for(size_t i = 0; i < len; i++) {
        b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        
        if(b != 0) {    
            return false;
        }
    }
    BGIN19Field res = self_vermsg.final_input * other_vermsg.final_input;
    BGIN19Field p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    
    BGIN19Field diff = res - p_eval_r;
    if(diff != 0) {  
        return false;
    } 

    return true;
}

#endif