/*
 * SemiRingShare.h
 *
 */

#ifndef PROTOCOLS_SEMIRINGSHARE_H_
#define PROTOCOLS_SEMIRINGSHARE_H_


#include "Semi3RingShare.h"
#include "SemiRingProtocol.h"
#include "ReplicatedPrep2k.h"
#include "GC/square64.h"
#include "Math/Z2k.h"

#include "global_debug.hpp"


template<class T> class ReplicatedPrep2k;

template<int K>
class SemiRingShare : public Semi3RingShare<Z2<K>>
{
    typedef SemiRingShare This;
    typedef Z2<K> T;

public:
    // type for clear values in relevant domain
    typedef SignedZ2<K> clear;
    typedef clear open_type;

    // disable binary computation
    typedef GC::SemiHonestRepSecret bit_type;

    // opening facility
    typedef ReplicatedMC<SemiRingShare> MAC_Check;
    typedef MAC_Check Direct_MC;

    // multiplication protocol
    typedef SemiRingProtocol<SemiRingShare> Protocol;

    // preprocessing facility
    typedef ReplicatedPrep2k<SemiRingShare> LivePrep;

    // private input facility
    typedef ReplicatedInput<SemiRingShare> Input;

    // default private output facility (using input tuples)
    typedef SpecificPrivateOutput<SemiRingShare> PrivateOutput;

    typedef ReplicatedPO<This> PO;
    typedef SemiRingShare Honest;


    bool is_zero_share;
    static const bool has_split = true;

    // description used for debugging output
    static string type_string()
    {
        return "SemiRing " + T::type_string();
    }

    // used for preprocessing storage location
    static string type_short()
    {
        return "SR" + string(1, clear::type_char());
    }

    // size in bytes
    // must match assign/pack/unpack and machine-readable input/output

    SemiRingShare() {
        if (BUILDING_SHARE_PROCESS & SEMI_RING_SHARE_PROCESS) {
            cout << "In SemiRingShare()" << endl;
        }
    }

    template<class U>
    SemiRingShare(const FixedVec<U, 2>& other)
    {
        if (BUILDING_SHARE_PROCESS & SEMI_RING_SHARE_PROCESS) {
            cout << "In SemiRingShare(FixedVec<U, 2>)" << endl;
            cout << "other: " << other << endl;
            // cout << typeid(T).name() << " " << typeid(U).name() << endl;
        }
        FixedVec<T, 2>::operator=(other);
    }

    template<class U>
    static void split(vector<U>& dest, const vector<int>& regs, int n_bits,
            const SemiRingShare* source, int n_inputs,
            typename U::Protocol& protocol)
    {

        // cout << "In SemiRingShare::split()" << endl;

        auto& P = protocol.P;
        int my_num = P.my_num();
        int unit = GC::Clear::N_BITS;
        for (int k = 0; k < DIV_CEIL(n_inputs, unit); k++)
        {
            int start = k * unit;
            int m = min(unit, n_inputs - start);

            switch (regs.size() / n_bits)
            {
            case 3:
                for (int l = 0; l < n_bits; l += unit)
                {
                    int base = l;
                    int n_left = min(n_bits - base, unit);
                    for (int i = base; i < base + n_left; i++)
                        dest.at(regs.at(3 * i + my_num) + k) = {};

                    for (int i = 0; i < 2; i++)
                    {
                        square64 square;

                        for (int j = 0; j < m; j++)
                            square.rows[j] = source[j + start][i].get_limb(
                                    l / unit);

                        square.transpose(m, n_left);

                        for (int j = 0; j < n_left; j++)
                        {
                            auto& dest_reg = dest.at(
                                    regs.at(3 * (base + j) + ((my_num + 2 - i) % 3))
                                            + k);
                            dest_reg[1 - i] = 0;
                            dest_reg[i] = square.rows[j];
                        }
                    }
                }
                break;
            case 2:
            {
                assert(n_bits <= 64);
                ReplicatedInput<U> input(P);
                input.reset_all(P);
                if (P.my_num() == 0)
                {
                    square64 square;
                    for (int j = 0; j < m; j++)
                        square.rows[j] = Integer(source[j + start].sum()).get();
                    square.transpose(m, n_bits);
                    for (int j = 0; j < n_bits; j++)
                        input.add_mine(square.rows[j], m);
                }
                else
                    for (int j = 0; j < n_bits; j++)
                        input.add_other(0);

                input.exchange();
                for (int j = 0; j < n_bits; j++)
                    dest.at(regs.at(2 * j) + k) = input.finalize(0, m);

                if (P.my_num() == 0)
                    for (int j = 0; j < n_bits; j++)
                        dest.at(regs.at(2 * j + 1) + k) = {};
                else
                {
                    square64 square;
                    for (int j = 0; j < m; j++)
                        square.rows[j] = Integer(source[j + start][P.my_num() - 1]).get();
                    square.transpose(m, n_bits);
                    for (int j = 0; j < n_bits; j++)
                    {
                        auto& dest_reg = dest.at(regs.at(2 * j + 1) + k);
                        dest_reg[P.my_num() - 1] = square.rows[j];
                        dest_reg[2 - P.my_num()] = {};
                    }
                }
                break;
            }
            default:
                throw runtime_error("number of split summands not implemented");
            }
        }
    }
};

#endif /* PROTOROCOLS_SEMIRINGSHARE_H_ */
