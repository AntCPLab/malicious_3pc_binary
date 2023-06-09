/*
 * Semi3Share.h
 * 
 */

#ifndef PROTOCOLS_SEMI3SHARE_H_
#define PROTOCOLS_SEMI3SHARE_H_

#include "Protocols/Rep3Share.h"
// #include "Protocols/Semi3Prep.h"
#include "Protocols/ReplicatedPrep.h"
#include "Protocols/Semi3Protocol.h"
#include "Math/FixedVec.h"
#include "Math/Integer.h"
#include "GC/ShareSecret.h"
#include "ShareInterface.h"
#include "Processor/Instruction.h"

template<class T> class ReplicatedPrep;
template<class T> class ReplicatedRingPrep;
template<class T> class ReplicatedPO;
template<class T> class SpecificPrivateOutput;


template<class T>
class Semi3Share : public RepShare<T, 2> {
	typedef RepShare<T, 2> super;
    typedef Semi3Share This;

public:
    typedef T clear;

    typedef Semi3Protocol<Semi3Share> Protocol;
    typedef ReplicatedMC<Semi3Share> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef Semi3Input<Semi3Share> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef ReplicatedPrep<Semi3Share> LivePrep;
    typedef ReplicatedRingPrep<Semi3Share> TriplePrep;
    typedef Semi3Share Honest;

    typedef Semi3Share Scalar;

    typedef GC::SemiHonestRepSecret bit_type;

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    const static bool expensive = false;
    const static bool variable_players = false;
    static const bool has_trunc_pr = true;
    static const bool malicious = false;

    static string type_short()
    {
        return "S" + string(1, clear::type_char());
    }
    static string type_string()
    {
        return "semi3 " + T::type_string();
    }
    static char type_char()
    {
        return T::type_char();
    }

    static Semi3Share constant(T value, int my_num,
            typename super::mac_key_type = {})
    {
        return Semi3Share(value, my_num);
    }

    Semi3Share()
    {
    }
    template<class U>
    Semi3Share(const U& other) :
            super(other)
    {
    }

    Semi3Share(T value, int my_num, const T& alphai = {})
    {
        (void) alphai;
        Semi3Protocol<Semi3Share>::assign(*this, value, my_num);
    }

    void assign(const char* buffer)
    {
        FixedVec<T, 2>::assign(buffer);
    }

    clear local_mul(const Semi3Share& other) const
    {
        auto a = (*this)[0].lazy_mul(other.lazy_sum());
        auto b = (*this)[1].lazy_mul(other[0]);
        return a.lazy_add(b);
    }
};

#endif