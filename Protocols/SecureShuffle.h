/*
 * SecureShuffle.h
 *
 */

#ifndef PROTOCOLS_SECURESHUFFLE_H_
#define PROTOCOLS_SECURESHUFFLE_H_

#include <vector>
using namespace std;

template<class T> class SubProcessor;

template<class T>
class SecureShuffle
{
    SubProcessor<T>& proc;
    vector<T> to_shuffle;
    vector<vector<T>> config;
    vector<T> tmp;
    int unit_size;

    vector<vector<vector<vector<T>>>> shuffles;
    size_t n_shuffle;
    bool exact;

    void player_round(int config_player);
    void generate(int config_player, int n_shuffle);

    void waksman(vector<T>& a, int depth, int start);
    void cond_swap(T& x, T& y, const T& b);

    void iter_waksman(bool reverse = false);
    void waksman_round(int size, bool inwards, bool reverse);

    void pre(vector<T>& a, size_t n, size_t input_base);
    void post(vector<T>& a, size_t n, size_t input_base);

public:
    SecureShuffle(vector<T>& a, size_t n, int unit_size,
            size_t output_base, size_t input_base, SubProcessor<T>& proc);

    SecureShuffle(SubProcessor<T>& proc);

    int generate(int n_shuffle);

    void apply(vector<T>& a, size_t n, int unit_size, size_t output_base,
            size_t input_base, int handle, bool reverse);

    void del(int handle);
};

#endif /* PROTOCOLS_SECURESHUFFLE_H_ */
