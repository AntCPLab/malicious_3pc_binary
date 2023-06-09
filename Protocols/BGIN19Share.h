/*
 * MaliciousRep3Share.h
 *
 */

#ifndef PROTOCOLS_BGIN19SHARE_H_
#define PROTOCOLS_BGIN19SHARE_H_

#include "SemiRingShare.h"
#include "SemiRingProtocol.h"
#include "SpdzWiseShare.h"
#include "SpdzWise.h"
#include "Math/Z2k.h"
#include "Rep3Share2k.h"

template<class T> class HashMaliciousRepMC;
template<class T> class MaliciousRepPrepWithBits;
template<class T> class MaliciousRepPO;
template<class T> class MaliciousRepPrep;
template<class T> class SpecificPrivateOutput;

namespace GC {
    class BGIN19Secret;
}

template <class T>
class BGIN19Share : public Rep3Share<T> {

    typedef Rep3Share<T> super;
    typedef BGIN19Share<T> This;

public:

    typedef Replicated<BGIN19Share<T>> Protocol;
    typedef HashMaliciousRepMC<BGIN19Share<T>> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<BGIN19Share<T>> Input;
    typedef MaliciousRepPO<BGIN19Share> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef Rep3Share<T> Honest;
    typedef MaliciousRepPrepWithBits<BGIN19Share> LivePrep;
    typedef MaliciousRepPrep<BGIN19Share> TriplePrep;
    typedef BGIN19Share prep_type;
    typedef T random_type;
    typedef This Scalar;

    typedef GC::MaliciousRepSecret bit_type;

    // indicate security relevance of field size
    typedef T mac_key_type;

    const static bool expensive = true;
    static const bool has_trunc_pr = false;
    static const bool malicious = true;

    static string type_short()
    {
        return "M3" + string(1, T::type_char());
    }

    static string type_string()
    {
        return "BGIN19 Secret " + T::type_string();
    }

    BGIN19Share()
    {
    }
    BGIN19Share(const T& other, int my_num, T alphai = {}) :
            super(other, my_num, alphai)
    {
    }
    template<class U>
    BGIN19Share(const U& other) : super(other)
    {
    }
};

template<class T> class NoLivePrep;
template<class T> class NotImplementedInput;
template<class T> class SpdzWiseMC;
template<class T> class SpdzWisePrep;
template<class T> class SpdzWiseInput;
template<class T> class SpdzWiseRingPrep;
template<class T> class SpdzWiseRing;



template <int K, int S>
class BGIN19RingShare : public SpdzWiseShare<BGIN19Share<Z2<K + S>>> {
    typedef BGIN19RingShare This;
    typedef SpdzWiseShare<BGIN19Share<Z2<K + S>>> super;

public:
    typedef SignedZ2<K> clear;
    typedef clear value_type;
    typedef clear open_type;
    typedef BGIN19Share<clear> open_part_type;

    typedef SpdzWiseMC<This> MAC_Check;
    typedef MAC_Check Direct_MC;

    typedef SpdzWiseRing<This> Protocol;
    typedef SpdzWiseRingPrep<This> LivePrep;
    typedef SpdzWiseInput<This> Input;
    typedef ::PrivateOutput<This> PrivateOutput;

    typedef GC::BGIN19Secret bit_type;

    static const int LENGTH = K;
    static const int SECURITY = S;

    static const bool has_split = true;

    BGIN19RingShare()
    {
    }

    template<class T>
    BGIN19RingShare(const T& other) :
            super(other)
    {
    }

    template<class T, class U>
    BGIN19RingShare(const T &share, const U &mac) :
            super(share, mac)
    {
    }

    template<class U>
    static void split(vector<U>& dest, const vector<int>& regs, int n_bits,
            const BGIN19RingShare* source, int n_inputs,
            typename U::Protocol& protocol)
    {
        vector<Rep3Share2<K>> shares(n_inputs);
        for (int i = 0; i < n_inputs; i++)
            shares[i] = source[i].get_share();
        Rep3Share2<K>::split(dest, regs, n_bits, shares.data(), n_inputs, protocol);
    }

    static void shrsi(SubProcessor<This>& proc, const Instruction& inst)
    {
        typename This::part_type::Honest::Protocol protocol(proc.P);
        protocol.init_mul();
        for (int i = 0; i < inst.get_size(); i++)
        {
            auto& dest = proc.get_S_ref(inst.get_r(0) + i);
            auto& source = proc.get_S_ref(inst.get_r(1) + i);
            dest.set_share(Rep3Share2<K>(source.get_share()) >> inst.get_n());
            protocol.prepare_mul(dest.get_share(), proc.MC.get_alphai());
        }
        protocol.exchange();
        for (int i = 0; i < inst.get_size(); i++)
        {
            auto& dest = proc.get_S_ref(inst.get_r(0) + i);
            dest.set_mac(protocol.finalize_mul());
            proc.protocol.add_to_check(dest);
        }
    }
};

template <class T>
using BGIN19FieldShare = SpdzWiseShare<BGIN19Share<T>>;

#endif /* PROTOCOLS_BGIN19SHARE_H_ */
