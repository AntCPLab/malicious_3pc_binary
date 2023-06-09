#ifndef PROTOCOLS_BINARYCHECK_HPP_
#define PROTOCOLS_BINARYCHECK_HPP_

#include "BinaryCheck.h"

#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;

void print_uint128(uint128_t x) {
    if (x > 9) print_uint128(x / 10);
    putchar(x % 10 + '0');
}

#define show_uint128(value) \
    cout << #value << " = "; \
    print_uint128(value); \
    cout << endl; 

template <class _T>
DZKProof Malicious3PCProtocol<_T>::_prove(
    size_t node_id,
    Field** masks,
    size_t batch_size, 
    Field sid
) {
    size_t k = OnlineOptions::singleton.k_size; 
    size_t k2 = OnlineOptions::singleton.k2_size;

    #ifdef DEBUG_OURS
        cout << "in _prove" << endl;
        // cout << "batch_size: " << T << ", s: " << s << endl;
    #endif

    vector<vector<Field>> p_evals_masked;
    size_t k_max = k > k2 ? k : k2;
    // Evaluations of polynomial p(X)
    Field* eval_p_poly = new Field[2 * k_max - 1];  

    Field** base = new Field*[k_max - 1];
    for (size_t i = 0; i < k_max - 1; i++) {
        base[i] = new Field[k_max];
    }

    Field** eval_result = new Field*[k_max];
    for(size_t i = 0; i < k_max; i++) {
        eval_result[i] = new Field[k_max];
    }

    Field* eval_base = new Field[k_max];

    // ===============================  First Round  ===============================

    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now();
    #endif

    // Vectors of masked evaluations of polynomial p(X)
    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);

    // cout << "cp 1.5" << endl;

    ShareTupleBlock quarter_k_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    size_t cur_quarter_k_blocks_id = 0;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    // assuming k % 4 = 0
    size_t quarter_k = k / 4;
    // cout << "block_cols_num: " << block_cols_num << endl;
    // cout << "total_blocks_num: " << total_blocks_num << endl;

    size_t padded_s = block_cols_num * BLOCK_SIZE;
    s = padded_s;

    for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

        // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
        if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
            for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                quarter_k_blocks[i] = ShareTupleBlock();
        }
        else {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
        }
        
        for(size_t i = 0; i < quarter_k; i++) { 
            // cout << "i:" << i << endl;

            ShareTupleBlock row_block = quarter_k_blocks[i];
            long a = row_block.input1.first;
            long c = row_block.input2.first;
            long e = (a & c) ^ row_block.result.first ^ row_block.rho.first;
            
            for(size_t j = 0; j < quarter_k; j++) {  

                ShareTupleBlock col_block = quarter_k_blocks[j];
                    
                long b = col_block.input2.second;
                long d = col_block.input1.second;
                long f = col_block.rho.second;

                Field sum1, sum2, sum = 0;
                // Field sum = 0;

                for(size_t row_entry_id = 0; row_entry_id < 4; row_entry_id++) {
                    for(size_t col_entry_id = 0; col_entry_id < 4; col_entry_id++) {
                    long tmp1 = 0, tmp2, tmp3, tmp4;
                        switch(row_entry_id) {
                            case 0: {
                                switch(col_entry_id) {
                                    // g_1 * h_1 = -2abcd(1-2e)(1-2f) = -2abcd + 4abcde + 4abcdf - 8abcdef
                                    case 0:
                                        tmp1 = a & b & c & d;
                                        break;
                                    // g_1 * h_2 = -2acd(1-2e)(1-2f) = -2acd + 4acde + 4acdf - 8acdef
                                    case 1:
                                        tmp1 = a & c & d;
                                        break;
                                    // g_1 * h_3 = -2abc(1-2e)(1-2f) = -2abc + 4abce + 4abcf - 8abcef
                                    case 2:
                                        tmp1 = a & b & c;
                                        break; 
                                    // g_1 * h_4 = -2ac(1-2e)(1-2f) = -2ac + 4ace + 4acf - 8acef
                                    case 3:
                                        tmp1 = a & c;
                                        break; 
                                } 

                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;

                                sum1 = -2 * (tmp1 >> 32) + 4 * ((tmp2 >> 32) + (tmp3 >> 32)) - 8 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = -2 * (tmp1 & 0xFFFFFFFF) + 4 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) - 8 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);

                                // sum = Mersenne::neg(2 * ((tmp1 >> 32) + (tmp1 & 0x00000000FFFFFFFF)));
                                // sum += 4 * ((tmp2 >> 32) + (tmp2 & 0x00000000FFFFFFFF));
                                // sum += 4 * ((tmp3 >> 32) + (tmp3 & 0x00000000FFFFFFFF));
                                // sum += Mersenne::neg(8 * ((tmp4 >> 32) + (tmp1 & 0x00000000FFFFFFFF)));
                                
                                break;
                            }

                            case 1: {
                                switch(col_entry_id) {
                                    // g_2 * h_1 = bcd(1−2e)(1−2f) = bcd - 2bcde - 2bcdf + 4bcdef
                                    case 0:
                                        tmp1 = b & c & d;
                                        break;
                                    // g_2 * h_2 = cd(1−2e)(1−2f) = cd - 2cde - 2cdf + 4cdef
                                    case 1:
                                        tmp1 = c & d;
                                        break; 
                                    // g_2 * h_3 = bc(1−2e)(1−2f) = bc - 2bce - 2bcf + 4bcef
                                    case 2:
                                        tmp1 = b & c;
                                        break; 
                                    case 3:
                                        // g_2 * h_3 = c(1−2e)(1−2f) = c - 2ce - 2cf + 4cef
                                        tmp1 = c;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;

                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);

                                // sum = (tmp1 >> 32) + (tmp1 & 0x00000000FFFFFFFF);
                                // sum += Mersenne::neg(2 * ((tmp2 >> 32) + (tmp2 & 0x00000000FFFFFFFF)));
                                // sum += Mersenne::neg(2 * ((tmp3 >> 32) + (tmp3 & 0x00000000FFFFFFFF)));
                                // sum += 4 * ((tmp4 >> 32) + (tmp1 & 0x00000000FFFFFFFF));
                                
                                break;
                            }

                            case 2: {
                                switch(col_entry_id) {
                                    // g_3 * h_1 = abd(1−2e)(1−2f) = abd - 2abde - 2abdf + 4abdef
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_3 * h_2 = ad(1−2e)(1−2f) = ad - 2ade - 2adf + 4adef
                                    case 1:
                                        tmp1 = a & d;
                                        break; 
                                    // g_3 * h_3 = ab(1−2e)(1−2f) = ab - 2abe - 2abf + 4abef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_3 * h_4 = a(1−2e)(1−2f) = a - 2ae - 2af + 4aef
                                    case 3:
                                        tmp1 = a;
                                        break; 
                                }
                                break; 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                               
                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::modp(sum1 + sum2);

                                // sum = (tmp1 >> 32) + (tmp1 & 0x00000000FFFFFFFF);
                                // sum += Mersenne::neg(2 * ((tmp2 >> 32) + (tmp2 & 0x00000000FFFFFFFF)));
                                // sum += Mersenne::neg(2 * ((tmp3 >> 32) + (tmp3 & 0x00000000FFFFFFFF)));
                                // sum += 4 * ((tmp4 >> 32) + (tmp1 & 0x00000000FFFFFFFF));
                                
                                break;
                            }
                                
                            case 3: {
                                switch(col_entry_id) {
                                    // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (-1/2) * bd + bde + bdf - 2bdef
                                    // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (bd - 2bde - 2bdf + 4bdef) * (-1/2)
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_4 * h_2 = d(1−2e)(1−2f) * (-1/2) = (-1/2) * d + de + df - 2def
                                    case 1:
                                        tmp1 = d;
                                        break; 
                                    // g_4 * h_3 = b(1−2e)(1−2f) * (-1/2) = (-1/2) * b + be + bf - 2bef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_4 * h_4 = (1−2e)(1−2f) * (-1/2) = (-1/2) + e + f - 2ef
                                    case 3:
                                        tmp1 = 1;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                
                                sum1 = (tmp1 >> 32) - 2 * ((tmp2 >> 32) + (tmp3 >> 32)) + 4 * (tmp4 >> 32) + Mersenne::PR;
                                sum2 = (tmp1 & 0xFFFFFFFF) - 2 * ((tmp2 & 0xFFFFFFFF) + (tmp3 & 0xFFFFFFFF)) + 4 * (tmp4 & 0xFFFFFFFF) + Mersenne::PR;
                                sum = Mersenne::mul(neg_two_inverse, Mersenne::modp(sum1 + sum2));
                                
                                // sum = Mersenne::mul(neg_two_inverse, ((tmp1 >> 32) + (tmp1 & 0x00000000FFFFFFFF)));
                                // sum += (tmp2 >> 32) + (tmp2 & 0x00000000FFFFFFFF);
                                // sum += (tmp3 >> 32) + (tmp3 & 0x00000000FFFFFFFF);
                                // sum += Mersenne::neg(2 * ((tmp4 >> 32) + (tmp1 & 0x00000000FFFFFFFF)));

                                break; 
                            }
                        }
                        
                        eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id] = Mersenne::add(eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id], sum);
                    }
                }
            }
        }
        cur_quarter_k_blocks_id += quarter_k;
    }

    for(size_t i = 0; i < k; i++) {
        eval_p_poly[i] = eval_result[i][i];
    }

    for(size_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(size_t j = 0; j < k; j++) {
            for (size_t l = 0; l < k; l++) {
                // eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
                eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
            }
        }
    }

    #ifdef TIMING
        auto end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute p evals) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    uint16_t cnt = 0;

    vector<Field> ss(2 * k - 1);       
    for(size_t i = 0; i < 2 * k - 1; i++) {           
        // ss[i] = eval_p_poly[i] - masks[cnt][i];
        ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
    }
    p_evals_masked.push_back(ss);

    // cout << "cp 2" << endl;

    transcript_hash.append_msges(ss);
    Field r = transcript_hash.get_challenge();

    Langrange::evaluate_bases(k, r, eval_base);

    s *= 4;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;

    // cout << "s: " << s << endl;
    // cout << "k2: " << k2 << endl;

    Field **input_left, **input_right;
    input_left = new Field*[k2];
    input_right = new Field*[k2];

    for(size_t i = 0; i < k2; i++) {
        input_left[i] = new Field[s];
        input_right[i] = new Field[s];
    }

    size_t index = 0;
    cur_quarter_k_blocks_id = 0;

    // new matrix: total size = s * 4 = 80w, number of rows: k2 = 8, number of cols: 80w / 8 = 10w

    // generate two lookup tables
    // size_t bits_num = quarter_k / 2 * 3;

    size_t two_powers;

    size_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_left_table1 = new Field[table_size]; 
    Field* input_left_table2 = new Field[table_size];
    Field* input_right_table1 = new Field[table_size]; 
    Field* input_right_table2 = new Field[table_size];
    // bool* ace_bits = new bool[bits_num];

    for (size_t i = 0; i < table_size; i++) { 
        // i = 0, ..., 4095, 000000000000, ..., 111111111111, each i represents a combination of the 12 bits e^(4),c^(4),a^(4), ..., e^(1),c^(1),a^(1)
        // 12 bits for e^(4),e^(3),e^(2),e^(1), ..., a^(4),a^(3),a^(2),a^(1)

        uint128_t left_sum1 = 0, left_sum2 = 0, right_sum1 = 0, right_sum2 = 0, tmp;
        size_t id1 = 0, id2 = quarter_k / 2;
        for (size_t j = 0; j < quarter_k / 2; j++) {
            // j = 0, 1, 2, 3
            // (e, c, a) = (bits_num[j * 3 + 2], bits_num[j * 3 + 1], bits_num[j * 3])
            // the same for (f, d, b)
            bool ab = i & (1 << (j * 3)); // bug: 1 << j * 3
            bool cd = i & (1 << (j * 3 + 1));
            bool ef = i & (1 << (j * 3 + 2)); // bug: j + 3 + 2

            left_sum1 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]) : 0;
            right_sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            id1++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            tmp = ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            left_sum1 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1];
            right_sum1 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];

            left_sum2 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
            right_sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            id2++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;
            
            tmp = ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;

            left_sum2 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id2];
            right_sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
        }
        input_left_table1[i] = Mersenne::modp_128(left_sum1);
        input_left_table2[i] = Mersenne::modp_128(left_sum2);
        input_right_table1[i] = Mersenne::modp_128(right_sum1);
        input_right_table2[i] = Mersenne::modp_128(right_sum2);
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    // Batchsize = 640w, total_blocks_num = 640w/64 = 10w, fetching k/4 = 8 blocks per time, needs 12500 times
    // k = 32, s = 640w/32 = 20w, block_cols_num = 20w/64 = 3125, totally 3125 cols of blocks, 3125 * 4 = 12500

    // 12
    size_t bits_num = quarter_k / 2 * 3;
    long* bit_blocks_left1 = new long[bits_num];
    long* bit_blocks_left2 = new long[bits_num];
    long* bit_blocks_right1 = new long[bits_num];
    long* bit_blocks_right2 = new long[bits_num];

    for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {

        // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
        if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
            for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                quarter_k_blocks[i] = ShareTupleBlock();
        }
        else {
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
        }

        // i = 0, 1, 2, 3
        for (size_t i = 0; i < quarter_k / 2; i++) {
            ShareTupleBlock cur_block = quarter_k_blocks[i];

            bit_blocks_left1[i * 3] = cur_block.input1.first;
            bit_blocks_left1[i * 3 + 1] = cur_block.input2.first;
            bit_blocks_left1[i * 3 + 2] = (cur_block.input1.first & cur_block.input2.first) ^ (cur_block.result.first) ^ (cur_block.rho.first);

            bit_blocks_right1[i * 3] = cur_block.input2.second;
            bit_blocks_right1[i * 3 + 1] = cur_block.input1.second;
            bit_blocks_right1[i * 3 + 2] = cur_block.rho.second;
            
            #ifdef DEBUG_OURS_CORRECTNESS_DATA
                cout << "cur_block.input1.first (left): " << cur_block.input1.first << endl;
                cout << "cur_block.input2.second (right): " << cur_block.input2.second << endl;
            #endif

            cur_block = quarter_k_blocks[i + quarter_k / 2];

            bit_blocks_left2[i * 3] = cur_block.input1.first;
            bit_blocks_left2[i * 3 + 1] = cur_block.input2.first;
            bit_blocks_left2[i * 3 + 2] = (cur_block.input1.first & cur_block.input2.first) ^ (cur_block.result.first) ^ (cur_block.rho.first);

            bit_blocks_right2[i * 3] = cur_block.input2.second;
            bit_blocks_right2[i * 3 + 1] = cur_block.input1.second;
            bit_blocks_right2[i * 3 + 2] = cur_block.rho.second;
        }

        size_t group_num = 5;

        // bit_id = 0,1, ..., 12
        for (size_t bit_id = 0; bit_id < 13; bit_id++) {

            // last group
            if (bit_id == 12) 
                group_num = 4;

            // group_id = 0-4 or 0-3 (for the last group)
            for (size_t group_id = 0; group_id < group_num; group_id++) {

                // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                // ......
                // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                size_t overall_bit_id = group_id * 13 + bit_id;
                size_t cur_index = index + overall_bit_id;
                size_t row = cur_index / s;
                size_t col = cur_index % s;

                if (cur_index >= s0) {
                    // cout << "cp 4" << endl;
                    if (row >= k2)
                        break;
                    else {
                        input_left[row][col] = input_right[row][col] = 0;
                        continue;
                    }
                }

                size_t left_id1 = 0, left_id2 = 0, right_id1 = 0, right_id2 = 0;

                for (size_t j = 0; j < bits_num; j++) {
                    left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                    left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                    right_id2 ^= ((bit_blocks_right2[j] >> overall_bit_id) << j);
                }

                // bit index in the 32-bit integer number, representing 2^(overall_bit_id % 32)
                two_powers = (uint64_t)1 << (overall_bit_id % 32);
                input_left[row][col] = Mersenne::mul(Mersenne::add(input_left_table1[left_id1 & 0xC], input_left_table2[left_id2 & 0xC]), two_powers);
                input_right[row][col] = Mersenne::mul(Mersenne::add(input_right_table1[right_id1 & 0xC], input_right_table2[right_id2 & 0xC]), two_powers);   
            }
        }

        index += BLOCK_SIZE;
        cur_quarter_k_blocks_id += quarter_k;
    }

    cnt++;

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    Langrange::get_bases(k2, base);

    while(true){
        // auto start = std::chrono::high_resolution_clock::now();

        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < k2; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

        for(size_t i = 0; i < k2; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(size_t i = 0; i < k2 - 1; i++) {
            eval_p_poly[i + k2] = 0;
            for(size_t j = 0; j < k2; j++) {
                for (size_t l = 0; l < k2; l++) {
                    // eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
                    eval_p_poly[i + k2] = Mersenne::add(eval_p_poly[i + k2], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }

        vector<Field> ss(2 * k2 - 1);       
        for(size_t i = 0; i < 2 * k2 - 1; i++) {           
            // ss[i] = eval_p_poly[i] - masks[cnt][i];
            // cout << "i" << i << endl;
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            // cout << "breaking" << endl;
            break;
        }
        
        transcript_hash.append_msges(ss);
        Field r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;
        // cout << "cp 3, s: " << s << endl;
       
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < s; j++) {
                index = i * s + j;

                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        // temp_result += eval_base[l] * input_left[l][index];
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }
                    input_left[i][j] = Mersenne::modp_128(temp_result);

                    temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        // temp_result += eval_base[l] * input_right[l][index];
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
        // cout << "cp 4" << endl;
        cnt++;
    }

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    #endif

    // cout << "cp 3" << endl;

    // for(size_t i = 0; i < k; i++) {
    //     delete[] eval_result[i];
    // }
    // delete[] eval_result;
    // delete[] eval_p_poly;

    // for (size_t i = 0; i < k - 1; i++) {
    //     delete[] base[i];
    // }
    // delete[] base;
    // delete[] eval_base;

    // for(size_t i = 0; i < k; i++) {
    //     delete[] input_left[i];
    //     delete[] input_right[i];
    // }

    // delete[] input_left;
    // delete[] input_right;

    // for (size_t j = 0; j < cnt; j ++) {
    //     delete[] masks[j];
    // }
    // delete[] masks;

    DZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

template <class _T>
VerMsg Malicious3PCProtocol<_T>::_gen_vermsg(
    DZKProof proof, 
    size_t node_id,
    Field** masks_ss,
    size_t batch_size, 
    Field sid,
    size_t prover_ID,
    size_t party_ID
) {
    // cout << "in _gen_vermsg " << endl;
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;

    size_t k_max = k > k2 ? k : k2;

    Field* eval_base = new Field[k_max];
    Field* eval_base_2k = new Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================

    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(4 * s) / log(k2) + 2;
    size_t quarter_k = k / 4;

    vector<Field> b_ss(len);
    Field final_input = 0, final_result_ss = 0;

    size_t cnt = 0;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);

    transcript_hash.append_msges(proof.p_evals_masked[cnt]);

    Field out_ss = 0, sum_ss = 0;

    // recover proof
    // two 32-bit integers per 64 bits
    size_t two_powers = ((unsigned long)0xFFFFFFFF - 1) * 2;

    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;

    #ifdef DEBUG_OURS_CORRECTNESS
        if (prev_party) cout << endl << "prev_party" << endl;
        else cout << endl << "next_party" << endl;
    #endif 

    if (prev_party) {
        out_ss = Mersenne::mul(neg_two_inverse, two_powers * batch_size);
        for(size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
        } 
    } else {
        out_ss = 0;
        for(size_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }

    // compute random linear combination on the first k outputs using betas
    for (size_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[cnt][j];
    }

    b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);
    
    // new evaluations at random point r

    Field r = transcript_hash.get_challenge();
    Langrange::evaluate_bases(k, r, eval_base);

    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    size_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    size_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    size_t cur_quarter_k_blocks_id = 0;
    ShareTupleBlock quarter_k_blocks[k];

    size_t padded_s = block_cols_num * BLOCK_SIZE;
    s = padded_s;

    s *= 4;
    size_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
    size_t index = 0;
 
    // cout << "cp 3" << endl;

    Field **input = new Field*[k2];
    for(size_t i = 0; i < k2; i++) {
        input[i] = new Field[s];
    }

    cur_quarter_k_blocks_id = 0;

    // generate two lookup tables
    size_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_table1 = new Field[table_size]; 
    Field* input_table2 = new Field[table_size];

    #ifdef TIMING
        auto start = std::chrono::high_resolution_clock::now(), end = start;
    #endif

    // uint32_t* shift_table = new uint32_t[quarter_k / 2 * 3];
    // for (size_t i = 0; i < quarter_k / 2 * 3; i++) {
    //     shift_table[i] = 1 << i;
    // }

    if (prev_party) {
        // Right Part
        for (size_t i = 0; i < table_size; i++) { 
            uint128_t sum1 = 0, sum2 = 0;
            size_t id1 = 0, id2 = quarter_k / 2;
            for (size_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];

                sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        #ifdef TIMING
                end = std::chrono::high_resolution_clock::now();
                cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

                start = std::chrono::high_resolution_clock::now();
        #endif

        size_t bits_num = quarter_k / 2 * 3;
        
        long* bit_blocks_right1 = new long[bits_num];
        long* bit_blocks_right2 = new long[bits_num];

        for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
            // cout << "block_col_id: " << block_col_id << endl;

            // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
            if (block_col_id == block_cols_num * 4 - 1 && total_blocks_num - cur_quarter_k_blocks_id < quarter_k) {
                memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * (total_blocks_num - cur_quarter_k_blocks_id));
                for (size_t i = total_blocks_num - cur_quarter_k_blocks_id ; i < quarter_k; i++)
                    quarter_k_blocks[i] = ShareTupleBlock();
            }
            else {
                memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * quarter_k);
            }

            // i = 0, 1, 2, 3
            for (size_t i = 0; i < quarter_k / 2; i++) {
                ShareTupleBlock cur_block = quarter_k_blocks[i];

                bit_blocks_right1[i * 3] = cur_block.input2.first;
                bit_blocks_right1[i * 3 + 1] = cur_block.input1.first;
                bit_blocks_right1[i * 3 + 2] = cur_block.rho.first;

                cur_block = quarter_k_blocks[i + quarter_k / 2];

                bit_blocks_right2[i * 3] = cur_block.input2.first;
                bit_blocks_right2[i * 3 + 1] = cur_block.input1.first;
                bit_blocks_right2[i * 3 + 2] = cur_block.rho.first;
            }

            size_t group_num = 5;

            // bit_id = 0,1, ..., 12
            for (size_t bit_id = 0; bit_id < 13; bit_id++) {

                // last group
                if (bit_id == 12) 
                    group_num = 4;

                // group_id = 0-4 or 0-3 (for the last group)
                for (size_t group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                    // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                    // ......
                    // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                    // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                    size_t overall_bit_id = group_id * 13 + bit_id;
                    size_t cur_index = index + overall_bit_id;
                    size_t row = cur_index / s;
                    size_t col = cur_index % s;

                    if (cur_index >= s0) {
                        // cout << "cp 4" << endl;
                        if (row >= k2)
                            break;
                        else {
                            input[row][col] = 0;
                            continue;
                        }
                    }

                    size_t right_id1 = 0, right_id2 = 0;

                    for (size_t j = 0; j < bits_num; j++) {
                        right_id1 ^= ((bit_blocks_right1[j] >> overall_bit_id) << j);
                        right_id2 ^= ((bit_blocks_right2[j] >> overall_bit_id) << j);
                    }

                    two_powers = (uint64_t)1 << (overall_bit_id % 32);
                    input[row][col] = Mersenne::mul(Mersenne::add(input_table1[right_id1 & 0xC], input_table2[right_id2 & 0xC]), two_powers);   
        
                }
            }

            index += 64;
            cur_quarter_k_blocks_id += quarter_k;
        }
    }
    else {
        // Left Part
        for (size_t i = 0; i < table_size; i++) { 
            uint128_t sum1 = 0, sum2 = 0;
            size_t id1 = 0, id2 = quarter_k / 2;
            for (size_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1];

                sum2 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id2];
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        #ifdef TIMING
                end = std::chrono::high_resolution_clock::now();
                cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

                start = std::chrono::high_resolution_clock::now();
        #endif

        size_t bits_num = quarter_k / 2 * 3;

        long* bit_blocks_left1 = new long[bits_num];
        long* bit_blocks_left2 = new long[bits_num];

        for (size_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
            // cout << "block_col_id: " << block_col_id << endl;

            // fetch k/4 tuple_blocks, containing k / 4 * BLOCKSIZE bit tuples
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));

            // i = 0, 1, 2, 3
            for (size_t i = 0; i < quarter_k / 2; i++) {
                ShareTupleBlock cur_block = quarter_k_blocks[i];

                bit_blocks_left1[i * 3] = cur_block.input1.second;
                bit_blocks_left1[i * 3 + 1] = cur_block.input2.second;
                bit_blocks_left1[i * 3 + 2] = (cur_block.input1.second & cur_block.input2.second) ^ (cur_block.result.second) ^ (cur_block.rho.second);

                cur_block = quarter_k_blocks[i + quarter_k / 2];

                bit_blocks_left2[i * 3] = cur_block.input1.second;
                bit_blocks_left2[i * 3 + 1] = cur_block.input2.second;
                bit_blocks_left2[i * 3 + 2] = (cur_block.input1.second & cur_block.input2.second) ^ (cur_block.result.second) ^ (cur_block.rho.second);
            }

            size_t group_num = 5;

            // bit_id = 0,1, ..., 12
            for (size_t bit_id = 0; bit_id < 13; bit_id++) {

                // last group
                if (bit_id == 12) 
                    group_num = 4;

                // group_id = 0-4 or 0-3 (for the last group)
                for (size_t group_id = 0; group_id < group_num; group_id++) {

                    // bit_id = 0:  overall_bit_id = 0, 13, 26, 39, 52
                    // bit_id = 1:  overall_bit_id = 1, 14, 27, 40, 53
                    // ......
                    // bit_id = 11: overall_bit_id = 11, 24, 37, 50, 63
                    // bit_id = 12: overall_bit_id = 12, 25, 38, 51
                    size_t overall_bit_id = group_id * 13 + bit_id;
                    size_t cur_index = index + overall_bit_id;
                    size_t row = cur_index / s;
                    size_t col = cur_index % s;

                    if (cur_index >= s0) {
                        // cout << "cp 4" << endl;
                        if (row >= k2)
                            break;
                        else {
                            input[row][col] = 0;
                            continue;
                        }
                    }

                    size_t left_id1 = 0, left_id2 = 0;

                    for (size_t j = 0; j < bits_num; j++) {
                        left_id1 ^= ((bit_blocks_left1[j] >> overall_bit_id) << j);
                        left_id2 ^= ((bit_blocks_left2[j] >> overall_bit_id) << j);
                    }
                    
                    two_powers = (uint64_t)1 << (overall_bit_id % 32);
                    input[row][col] = Mersenne::mul(Mersenne::add(input_table1[left_id1 & 0xC], input_table2[left_id2 & 0xC]), two_powers);   
                }
            }

            index += 64;
            cur_quarter_k_blocks_id += quarter_k;
        }
    }

    cnt++;

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();
    #endif

    // cout << "cp 4" << endl;

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if(prev_party) {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
            } 
        } else {
            for(size_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        sum_ss = 0;
        for(size_t j = 0; j < k2; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        r = transcript_hash.get_challenge();
        Langrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
        uint128_t temp_result = 0;
        for(size_t i = 0; i < 2 * k2 - 1; i++) {
            temp_result += (uint128_t)eval_base_2k[i] * (uint128_t)proof.p_evals_masked[cnt][i];
        }
        out_ss = Mersenne::modp_128(temp_result);

        // b_ss[cnt] = sum_ss - out_ss;
        b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Langrange::evaluate_bases(k2, r, eval_base);
            
            for(size_t i = 0; i < k2; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Langrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);

            final_result_ss = Mersenne::inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

            break;
        }

        Langrange::evaluate_bases(k2, r, eval_base);
        s0 = s;
        s = (s - 1) / k2 + 1;
        for(size_t i = 0; i < k2; i++) {
            for(size_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(size_t l = 0; l < k2; l++) {
                        temp_result += (uint128_t)eval_base[l] * (uint128_t)input[l][index];
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

    #ifdef TIMING
        end = std::chrono::high_resolution_clock::now();
        cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    #endif

    // cout << "cp 5" << endl;

    // delete[] eval_base;
    // delete[] eval_base_2k;

    // delete[] input;

    // for (size_t j = 0; j < cnt; j ++) {
    //     delete[] masks_ss[j];
    // }
    // delete[] masks_ss;

    VerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );
    // cout << "cp 6" << endl;

    return vermsg;
}

template <class _T>
bool Malicious3PCProtocol<_T>::_verify(
    DZKProof proof, 
    VerMsg other_vermsg, 
    size_t node_id,
    Field** masks_ss,
    size_t batch_size, 
    Field sid,
    size_t prover_ID,
    size_t party_ID
) {
    // cout << "in _verify..." << endl;
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;
    
    size_t T = ((batch_size - 1) / k + 1) * k;
    size_t s = (T - 1) / k + 1;
    size_t len = log(4 * s) / log(k2) + 2;
    
    VerMsg self_vermsg = _gen_vermsg(proof, node_id, masks_ss, batch_size, sid, prover_ID, party_ID);

    Field b;
    // cout << "in _verify, cp 1" << endl;
    for(size_t i = 0; i < len; i++) {
        // b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        b = Mersenne::add(self_vermsg.b_ss[i], other_vermsg.b_ss[i]);
        
        if(b != 0) {    
            return false;
        }
    }
    // cout << "in _verify, cp 2" << endl;

    // Field res = self_vermsg.final_input + other_vermsg.final_input;
    // Field p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    Field res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    Field p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {   
        return false;
    } 

    return true;
}

#endif