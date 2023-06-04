/*
 * SemiSecret.cpp
 *
 */

#include "GC/ShareParty.h"
#include "GC/ShareSecret.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/DealerMC.h"
#include "SemiSecret.h"

namespace GC
{

template<class T, class V>
const int SemiSecretBase<T, V>::default_length;

inline
SemiSecret::MC* SemiSecret::new_mc(
        typename super::mac_key_type)
{
    if (OnlineOptions::singleton.direct)
        return new Direct_MC;
    else
        return new MC;
}

inline
DealerSecret::MC* DealerSecret::new_mc(
        typename super::mac_key_type)
{
    if (OnlineOptions::singleton.direct)
        return new Direct_MC;
    else
        return new MC;
}

template<class T, class V>
void SemiSecretBase<T, V>::trans(Processor<T>& processor, int n_outputs,
        const vector<int>& args)
{
    int N_BITS = default_length;
    for (int j = 0; j < DIV_CEIL(n_outputs, N_BITS); j++)
        for (int l = 0; l < DIV_CEIL(args.size() - n_outputs, N_BITS); l++)
        {
            square64 square;
            size_t input_base = n_outputs + l * N_BITS;
            for (size_t i = input_base;
                    i < min(input_base + N_BITS, args.size()); i++)
                square.rows[i - input_base] = processor.S[args[i] + j].get();
            square.transpose(
                    min(size_t(N_BITS), args.size() - n_outputs - l * N_BITS),
                    min(N_BITS, n_outputs - j * N_BITS));
            int output_base = j * N_BITS;
            for (int i = output_base; i < min(n_outputs, output_base + N_BITS);
                    i++)
            {
                processor.S[args[i] + l] = square.rows[i - output_base];
            }
        }
}

template<class T, class V>
void SemiSecretBase<T, V>::load_clear(int n, const Integer& x)
{
    this->check_length(n, x);
    *this = this->constant(x, ShareThread<T>::s().P->my_num());
}

template<class T, class V>
void SemiSecretBase<T, V>::bitcom(Memory<T>& S, const vector<int>& regs)
{
    *this = 0;
    for (unsigned int i = 0; i < regs.size(); i++)
        *this ^= (S[regs[i]] << i);
}

template<class T, class V>
void SemiSecretBase<T, V>::bitdec(Memory<T>& S,
        const vector<int>& regs) const
{
    for (unsigned int i = 0; i < regs.size(); i++)
        S[regs[i]] = (*this >> i) & 1;
}

template<class T, class V>
void SemiSecretBase<T, V>::reveal(size_t n_bits, Clear& x)
{
    auto& thread = ShareThread<T>::s();
    x = thread.MC->POpen(*this, *thread.P).mask(n_bits);
}

} /* namespace GC */
