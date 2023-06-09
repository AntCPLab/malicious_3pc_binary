/*
 * Semi3PC.h
 *
 */

#ifndef PROTOCOLS_SEMI3PROTOCOL_H_
#define PROTOCOLS_SEMI3PROTOCOL_H_

#include "Protocols/Replicated.h"
#include "Processor/Input.h"


// template <class T>
// class Semi3Protocol : public Replicated<T> {


//     array<octetStream, 2> os;
//     PointerVector<typename T::clear> add_shares;
//     typename T::clear dotprod_share;

//     template<class U>
//     void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
//     template<class U>
//     void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);


// public:
	
//     Semi3Protocol(Player& P) : Replicated<T>(P) {}
//     Semi3Protocol(const ReplicatedBase& other) : Replicated<T>(other) {}

//     void prepare_mul(const T& x, const T& y, int n = -1);
//     void exchange();
//     T finalize_mul(int n = -1);
	
// };


template <class T>
class Semi3Protocol : public ReplicatedBase, public ProtocolBase<T>
{
    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares;
    typename T::clear dotprod_share;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

public:
    static const bool uses_triples = false;

    Semi3Protocol(Player& P);
    Semi3Protocol(const ReplicatedBase& other);

    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
    }

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);

    void prepare_reshare(const typename T::clear& share, int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    T get_random();
    void randoms(T& res, int n_bits);

    void start_exchange();
    void stop_exchange();
};

// private input facility
template<class T>
class Semi3Input : public ReplicatedInput<T>
{

public:
    Semi3Input(SubProcessor<T>& proc) :
            ReplicatedInput<T>(proc)
    {
    }

    Semi3Input(SubProcessor<T>& proc, ReplicatedMC<T>& MC) :
            ReplicatedInput<T>(proc, MC)
    {
    }

    Semi3Input(typename T::MAC_Check& MC, Preprocessing<T>& prep, Player& P) :
            ReplicatedInput<T>(MC, prep, P)
    {
    }

    Semi3Input(SubProcessor<T>* proc, Player& P) :
            ReplicatedInput<T>(proc, P)
    {
    }

    Semi3Input(Player &P) :
            ReplicatedInput<T>(P)
    {
    }

};

#endif