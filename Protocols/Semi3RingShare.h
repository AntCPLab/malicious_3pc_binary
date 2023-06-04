/*
 * Rep3Share.h
 *
 */

#ifndef PROTOCOLS_SEMI3RINGSHARE_H_
#define PROTOCOLS_SEMI3RINGSHARE_H_

#include "Math/FixedVec.h"
#include "Math/Integer.h"
#include "Protocols/Replicated.h"
#include "Protocols/SemiRingProtocol.h"
#include "GC/ShareSecret.h"
#include "ShareInterface.h"
#include "Processor/Instruction.h"

#include "Protocols/Rep3Share.h"
#include "global_debug.hpp"

template<class T>
class Semi3RingShare : public RepShare<T, 2>
{
    typedef RepShare<T, 2> super;
    typedef Semi3RingShare This;

public:
    typedef T clear;

    typedef SemiRingProtocol<Semi3RingShare> Protocol;
    typedef ReplicatedMC<Semi3RingShare> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Semi3RingShare> Input;
    typedef ReplicatedPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef ReplicatedPrep<Semi3RingShare> LivePrep;
    typedef ReplicatedRingPrep<Semi3RingShare> TriplePrep;
    typedef Semi3RingShare Honest;

    typedef Semi3RingShare Scalar;

    typedef GC::SemiHonestRepSecret bit_type;

    const static bool needs_ot = false;
    const static bool dishonest_majority = false;
    const static bool expensive = false;
    const static bool variable_players = false;
    static const bool has_trunc_pr = true;
    static const bool malicious = false;
    bool is_zero_share = false;

    static string type_short()
    {
        return "S3" + string(1, clear::type_char());
    }
    static string type_string()
    {
        return "Semi3Ring " + T::type_string();
    }
    static char type_char()
    {
        return T::type_char();
    }

    static Semi3RingShare constant(T value, int my_num,
            typename super::mac_key_type = {})
    {
        return Semi3RingShare(value, my_num);
    }

    Semi3RingShare()
    {
        if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
            cout << "In Semi3RingShare()" << endl;
        }
    }
    template<class U>
    Semi3RingShare(const U& other) :
            super(other)
    {
        if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
            cout << "In Semi3RingShare(const U& other)" << endl;
        }
    }

    Semi3RingShare(T value, int my_num, const T& alphai = {})
    {

        if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
            cout << "In Semi3RingShare(T value, int my_num, const T& alphai = {})" << endl;
            cout << "assinging " << value << " to " << my_num << endl;
        }

        (void) alphai;

        SemiRingProtocol<Semi3RingShare>::assign(*this, value, my_num);
    }

    void assign(const char* buffer)
    {
        if (BUILDING_SHARE_PROCESS & SEMI3_RING_SHARE_PROCESS) {
            cout << "In Semi3RingShare::assign(const char* buffer)" << endl;
            cout << "assinging " << buffer << endl;
        }
        FixedVec<T, 2>::assign(buffer);
    }

    clear local_mul(const Semi3RingShare& other) const
    {
        auto a = (*this)[0].lazy_mul(other.lazy_sum());
        auto b = (*this)[1].lazy_mul(other[0]);
        return a.lazy_add(b);
    }
};

#endif /* PROTOCOLS_SEMI3RINGSHARE_H_ */
