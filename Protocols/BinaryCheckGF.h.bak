#ifndef PROTOCOLS_BINARYCHECK_H_
#define PROTOCOLS_BINARYCHECK_H_

#include <vector>
#include "Tools/Hash.h"
#include "Math/gf2nlong.h"

using namespace std;

typedef unsigned __int128 uint128_t;

// clock_t begin_time, finish_time;
class LocalHash {
    octetStream buffer;
public:

    // template <typename T>
    void update(const gf2n_long data) {
        buffer.store(data);
    }

    uint64_t final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        uint64_t result;
        hash.final().get(result);
        return result;
    }
};

template <class T>
struct DZKProof {
    vector<vector<T>> p_evals_masked;

    size_t get_size() {
        size_t size = 0;
        for (auto& v : p_evals_masked) {
            size += v.size();
        }
        return size;
    }

    uint64_t get_hash() {
        LocalHash hash;
        for (auto p_eval : p_evals_masked) {
            for (auto each : p_eval) {
                hash.update(each);
            }
        }
        return hash.final();
    }

    void pack(octetStream &os) {
        os.store(p_evals_masked.size());
        os.store(p_evals_masked[0].size());
        for (auto each: p_evals_masked) {
            for (T each_eval: each) {
                os.store(each_eval);
            }
        }
    }

    void unpack(octetStream &os) {
        size_t num_p_evals_masked = 0;
        size_t num_p_evals_masked_each = 0;

        os.get(num_p_evals_masked);
        os.get(num_p_evals_masked_each);
        p_evals_masked.resize(num_p_evals_masked);
        for (size_t i = 0; i < num_p_evals_masked; i++) {
            p_evals_masked[i].resize(num_p_evals_masked_each);
            for (size_t j = 0; j < num_p_evals_masked_each; j++) {
                os.get(p_evals_masked[i][j]);
            }
        }
    }

    void print_out() {
        cout << "proof: ";
        for(auto row: p_evals_masked) {
            for(auto x: row) {
                cout << x << " ";
            }
        }
        cout << endl;
    }
};

template <class T>
struct VerMsg {
    // vector<uint64_t> p_eval_ksum_ss;
    // vector<uint64_t> p_eval_r_ss;
    vector<T> b_ss;
    T final_input;
    T final_result_ss;

    VerMsg() {}
    // VerMsg(vector<uint64_t> p_eval_ksum_ss, vector<uint64_t> p_eval_r_ss, uint64_t final_input, uint64_t final_result_ss) {
    VerMsg(vector<T> b_ss, T final_input, T final_result_ss) {
        // this->p_eval_ksum_ss = p_eval_ksum_ss;
        // this->p_eval_r_ss = p_eval_r_ss;
        this->b_ss = b_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
    }

    size_t get_size() {
        // return p_eval_ksum_ss.size() + p_eval_r_ss.size() + 2;
        return b_ss.size() + 2;
    }

    uint64_t get_hash() {
        LocalHash hash;
        // for (uint64_t each: p_eval_ksum_ss) {
        //     hash.update(each);
        // }
        // for (uint64_t each: p_eval_r_ss) {
        //     hash.update(each);
        // }
        for (uint64_t each: b_ss) {
            hash.update(each);
        }
        hash.update(final_input);
        hash.update(final_result_ss);
        return hash.final();
    }

    void pack(octetStream &os) {
        // os.store(p_eval_ksum_ss.size());
        // for(uint64_t i = 0; i < p_eval_ksum_ss.size(); i++) {
        //     os.store(p_eval_ksum_ss[i]);
        // }
        // os.store(p_eval_r_ss.size());
        // for(uint64_t i = 0; i < p_eval_r_ss.size(); i++) {
        //     os.store(p_eval_r_ss[i]);
        // }
        os.store(b_ss.size());
        for(uint64_t i = 0; i < b_ss.size(); i++) {
            os.store(b_ss[i]);
        }
        os.store(final_input);
        os.store(final_result_ss);
    }

    void unpack(octetStream &os) {
        uint64_t size = 0;
        // os.get(size);
        // p_eval_ksum_ss.resize(size);
        // for(uint64_t i = 0; i < size; i++) {
        //     os.get(p_eval_ksum_ss[i]);
        // }
        // os.get(size);
        // p_eval_r_ss.resize(size);
        // for(uint64_t i = 0; i < size; i++) {
        //     os.get(p_eval_r_ss[i]);
        // }
        os.get(size);
        b_ss.resize(size);
        for(uint64_t i = 0; i < size; i++) {
            os.get(b_ss[i]);
        }
        os.get(final_input);
        os.get(final_result_ss);
    }
};

uint64_t get_rand();
uint64_t** get_bases(uint64_t n);
uint64_t* evaluate_bases(uint64_t n, uint64_t r);

void append_one_msg(LocalHash &hash, uint64_t msg);
void append_msges(LocalHash &hash, vector<uint64_t> msges);
uint64_t get_challenge(LocalHash &hash);

#endif