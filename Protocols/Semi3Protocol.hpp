/*
 * Semi3PC.cpp
 * 
 */

#ifndef PROTOCOLS_SEMI3PROTOCOL_HPP_
#define PROTOCOLS_SEMI3PROTOCOL_HPP_

#include "Semi3Protocol.h"

#include "Replicated.hpp"

#include "Math/Z2k.hpp"

// template <class T>
// T Semi3Protocol<T>::mul(const T& x, const T& y) {
// 	init_mul();
// 	prepare_mul(x, y);
// 	exchange();
// 	return finalize_mul();
// }


template <class T>
void Semi3Protocol<T>::prepare_mul(const T& x, const T& y, int n) {
	
	typename T::value_type tmp[3], add_share;
	int player_number = P.my_real_num();

	/*
	* For player 0:
	*	add_shares = {rz0, rz1, random, rxy-random}
	* 
	* For player 1:
	*	add_shares = {rz1, random, add_share}
	* 
	* For player 2:
	*	add_shares = {rz2, rxy-random, add_share}
	*/
	
	if (player_number == 0) {
		
		for (int i = 0; i < 2; i++) {
			tmp[i].randomize(shared_prngs[i], n);
			add_shares.push_back(tmp[i]);
		}

		tmp[2].randomize(shared_prngs[0], n);
		add_shares.push_back(tmp[2]);
		add_shares.push_back((x[0] + x[1]) * (y[0] + y[1]) - tmp[2]);
		
		add_shares[3].pack(os[0], n);
		P.send_relative(-1, os[0]);
	}
	else if (player_number == 1) {
		
		tmp[0].randomize(shared_prngs[1], n);
		add_shares.push_back(tmp[0]);
		tmp[1].randomize(shared_prngs[1], n);

		add_share = y[0] * (x[0] + x[1]) + y[1] * x[0] + tmp[1] - add_shares[0];
		os[1].reset_write_head();
		add_share.pack(os[0], n);

		add_shares.push_back(add_share);
		
	}
	else {
		tmp[0].randomize(shared_prngs[0], n);
		add_shares.push_back(tmp[0]);
		
		P.receive_relative(1, os[1]);
		tmp[1].unpack(os[1], n);

		add_share = x[0] * y[1] + x[1] * y[0] + tmp[1] - add_shares[0];
		os[1].reset_write_head();
		add_share.pack(os[0], n);

		add_shares.push_back(add_share);
	}
}

template <class T>
void Semi3Protocol<T>::exchange() {
	
	int player_number = P.my_real_num();
	typename T::value_type tmp;
	
	if (player_number == 0) {
		// do nothing
		;
	}
	else {
		P.pass_around(os[0], os[1], player_number - 1);
	}
}

template <class T>
inline T Semi3Protocol<T>::finalize_mul(int n) {
	
	int player_number = P.my_real_num();
	T result;

	if (player_number == 0) {
		result[0] = add_shares[0];
		result[1] = add_shares[1];
	}
	else {
		typename T::value_type tmp;
		
		tmp.unpack(os[1], n);

		tmp += add_shares[1];
		result[player_number - 1] = add_shares[0];
		result[2 - player_number] = tmp;
	}

	return result;
}


template<class T>
template<class U>
void Semi3Protocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Semi3Protocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}


template<class T>
Semi3Protocol<T>::Semi3Protocol(Player& P) : ReplicatedBase(P)
{
    assert(T::vector_length == 2);
}

template<class T>
Semi3Protocol<T>::Semi3Protocol(const ReplicatedBase& other) :
        ReplicatedBase(other)
{
}


template<class T>
void Semi3Protocol<T>::init_mul()
{
    for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template<class T>
void Semi3Protocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++)
        tmp[i].randomize(shared_prngs[i], n);
    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Semi3Protocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    this->rounds++;
}

template<class T>
void Semi3Protocol<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
}

template<class T>
inline void Semi3Protocol<T>::init_dotprod()
{
    init_mul();
    dotprod_share.assign_zero();
}

template<class T>
inline void Semi3Protocol<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Semi3Protocol<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T Semi3Protocol<T>::finalize_dotprod(int length)
{
    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

template<class T>
T Semi3Protocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
    return res;
}


template<class T>
void Semi3Protocol<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
template<class U>
void Semi3Protocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        false_type)
{
    assert(regs.size() % 4 == 0);
    assert(proc.P.num_players() == 3);
    assert(proc.Proc != 0);
    typedef typename T::clear value_type;
    int gen_player = 2;
    int comp_player = 1;
    bool generate = P.my_num() == gen_player;
    bool compute = P.my_num() == comp_player;
    ArgList<TruncPrTupleWithGap<value_type>> infos(regs);
    auto& S = proc.get_S();

    octetStream cs;
    ReplicatedInput<T> input(P);

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto r = G.get<value_type>();
                input.add_mine(info.upper(r));
                if (info.small_gap())
                    input.add_mine(info.msb(r));
                (r + S[info.source_base + i][0]).pack(cs);
            }
        P.send_to(comp_player, cs);
    }
    else
        input.add_other(gen_player);

    if (compute)
    {
        P.receive_player(gen_player, cs);
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto c = cs.get<value_type>() + S[info.source_base + i].sum();
                input.add_mine(info.upper(c));
                if (info.small_gap())
                    input.add_mine(info.msb(c));
            }
    }

    input.add_other(comp_player);
    input.exchange();
    init_mul();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
        {
            this->trunc_pr_counter++;
            auto c_prime = input.finalize(comp_player);
            auto r_prime = input.finalize(gen_player);
            S[info.dest_base + i] = c_prime - r_prime;

            if (info.small_gap())
            {
                auto c_dprime = input.finalize(comp_player);
                auto r_msb = input.finalize(gen_player);
                S[info.dest_base + i] += ((r_msb + c_dprime)
                        << (info.k - info.m));
                prepare_mul(r_msb, c_dprime);
            }
        }

    exchange();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
            if (info.small_gap())
                S[info.dest_base + i] -= finalize_mul()
                        << (info.k - info.m + 1);
}


#endif