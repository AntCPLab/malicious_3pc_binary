
#ifndef PROTOCOLS_SEMIRINGPROTOCOL_HPP_
#define PROTOCOLS_SEMIRINGPROTOCOL_HPP_

#include "SemiRingProtocol.h"
#include "Replicated.hpp"

#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"

#include "global_debug.hpp"
#include <ctime>
#include <chrono>

template <class T>
SemiRingProtocol<T>::SemiRingProtocol(Player &P) : ReplicatedBase(P)
{
	assert(T::vector_length == 2);
}


template <class T>
void SemiRingProtocol<T>::thread_handler() {
	typename T::value_type tmp;

	// cout << "Running new thread" << endl;

	if (os[1].empty())
		P.receive_relative(1, os[1]);
	
	// cout << T::clear::N_BYTES << endl;
	// cout << os[1].get_length() << endl;

	while (true) {

		wait();
		if (this->total_recv == this->dealed && this->waiting) {
			signal2();
			break;
		}
		
		add_shares.push_back(tmp_shares[this->dealed * 2]);
		// tmp_shares.pop();
		tmp.unpack(os[1], this->n_bits);
		tmp += tmp_shares[this->dealed * 2 + 1];
		// tmp_shares.pop();
		add_shares.push_back(tmp);
		tmp.pack(os[0], this->n_bits);
		this->dealed ++;

	}

	os[1].reset_read_head();
	// cout << "Thread closed" << endl;
}

template<class T>
void SemiRingProtocol<T>::init_mul() {

	if (LOG_LEVEL & SHOW_PROGRESS)
		cout << "Init mul " << time(0) << endl;

	// cout << mul_counter << endl;

    for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
	tmp_shares.clear();

	this->n_bits = -1;
	this->n_times = 0;
	this->total_recv = 0;
	this->count2 = 0;
	this->recv_running = false;
	this->waiting = false;
	this->dealed = 0;

	// cout << "Initial  end   at " << std::chrono::system_clock::now().time_since_epoch().count() << endl;
}


template <class T>
void SemiRingProtocol<T>::prepare_mul(const T& x, const T& y, int n) {
	
	this->n_bits = n;

    typename T::value_type tmp[3], add_share, tmp_random;
	int player_number = P.my_real_num();

	if (LOG_LEVEL & SHOW_PROGRESS)
		cout << "In prepare mul " << time(0) << endl;

	// if (LOG_LEVEL & SHOW_SHARE_DETAIL) {
	// 	printShare(x, "Source x: ");
	// 	printShare(y, "Source y: ");
	// }


	/*
	* For player 0:
	*	add_shares = {rz0, rz1}
	* 
	* For player 1:
	*	add_shares = {rz1, add_share}
	* 
	* For player 2:
	*	add_shares = {rz2, add_share}
	*/

	if (player_number == 0) {
	
		for (int i = 0; i < 2; i++) {
			tmp[i].randomize(shared_prngs[i], n);
			add_shares.push_back(tmp[i]);
		}

		tmp[2].randomize(shared_prngs[0], n);
		tmp[2] = (x[0] + x[1]) * (y[0] + y[1]) - tmp[2];	
		tmp[2].pack(os[0], n);

		if (LOG_LEVEL & SHOW_COMMUNICATION)	
			cout << "Send data" << tmp[2] << endl;

	}
	else if (player_number == 1) {

		tmp[0].randomize(shared_prngs[1], n);
		add_shares.push_back(tmp[0]);
		tmp_random = tmp[0];

		if (x.is_zero_share && false) {
			add_share = y[0] * x[0] + y[1] * x[0] - tmp_random;
		} 
		else if (y.is_zero_share && false) {
			add_share = x[0] * y[0] + x[1] * y[0] - tmp_random;
		}
		else {
			tmp[1].randomize(shared_prngs[1], n);
			add_share = y[0] * (x[0] + x[1]) + y[1] * x[0] + tmp[1] - tmp_random;
		}

	
		add_share.pack(os[0], n);

		if (LOG_LEVEL & SHOW_COMMUNICATION)
			cout << "Send data" << add_share << endl;

		add_shares.push_back(add_share);
	
	}
	else {

		if (!this->recv_running) {
			this->recv_running = true;
			this->recv_thread = std::thread(&SemiRingProtocol<T>::thread_handler, this);
		}

		tmp[0].randomize(shared_prngs[0], n);
		tmp_shares.push_back(tmp[0]);
		tmp_random = tmp[0];

		if (LOG_LEVEL & SHOW_COMMUNICATION)
			cout << "Receive data" << tmp[1] << endl;

		add_share = x[0] * y[1] + x[1] * y[0] - tmp_random;
		tmp_shares.push_back(add_share);
		this->total_recv ++;
		signal();
	}

}

template <class T>
void SemiRingProtocol<T>::exchange2() {
	int player_number = P.my_real_num();
	int another_player_number;
	typename T::value_type tmp;

	if (LOG_LEVEL & SHOW_PROGRESS)
		cout << "Start exchange " << time(0) << endl;

	if (player_number == 0) {
		// do nothing
		;
	}
	else {
		if (player_number == 1) {
			another_player_number = 2;
		}
		else {
			another_player_number = 1;
		}

		P.exchange(another_player_number, os[0], os[1]);
		
		this->rounds ++;
	}

}


template <class T>
void SemiRingProtocol<T>::exchange1() {
	int player_number = P.my_real_num();

	if (player_number == 1) {
		;
	}
	else if (player_number == 0) {
		P.send_relative(-1, os[0]);
	}
	else {
		this->waiting = true;
		signal();
		wait2();
		this->recv_thread.join();
		// cout << "Joined at" << std::chrono::system_clock::now().time_since_epoch().count() << endl;

	}

}

template <class T>
void SemiRingProtocol<T>::exchange() {

	std::chrono::_V2::system_clock::time_point start, end;

	if (LOG_LEVEL & SHOW_TIME_LOG) {
		start = std::chrono::high_resolution_clock::now();
		cout << "Start exchange at " << start.time_since_epoch().count() << endl;
	}

	exchange1();
	exchange2();

	if (LOG_LEVEL & SHOW_TIME_LOG) {
		end = std::chrono::high_resolution_clock::now();
		cout << "End   exchange at " << end.time_since_epoch().count() << endl;
		cout << "Exchange costs " << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << endl;
	}
    
}

template <class T>
inline T SemiRingProtocol<T>::finalize_mul(int n) {

    int player_number = P.my_real_num();
	T result;
	
	this->counter ++;
	this->bit_counter += n;

	if (LOG_LEVEL & SHOW_PROGRESS)
		cout << "Start finalizing mul " << time(0) << endl;

	if (player_number == 0) {
		result[0] = add_shares.next();
		result[1] = add_shares.next();
	}
	else {
		typename T::value_type tmp;
	
		tmp.unpack(os[1], n);

		if (LOG_LEVEL & SHOW_COMMUNICATION)
			cout << "Receive data" << tmp << endl;

		result[2 - player_number] = add_shares.next();
		tmp += add_shares.next();
	
		result[player_number - 1] = tmp;
	}

	result.is_zero_share = false;

	// if (LOG_LEVEL & SHOW_SHARE_DETAIL)
	// 	printShare(result, "Result: ");

	return result;
}


template<class T>
inline void SemiRingProtocol<T>::init_dotprod()
{
	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In init_dotprod()" << endl;
    }
    init_mul();
    dotprod_share.assign_zero();
	
	if (P.my_real_num() == 2) {
		this->recv_running = true;
		this->recv_thread = std::thread(&SemiRingProtocol<T>::thread_handler, this);
		this->waiting = false;
	}

	
}

template<class T>
inline void SemiRingProtocol<T>::prepare_dotprod(const T& x, const T& y)
{

	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In prepare_dotprod()" << endl;
    }

	int player_number = P.my_real_num();

	if (player_number == 0) {
		dotprod_share = dotprod_share.lazy_add((x[0] + x[1]) * (y[0] + y[1]));
	}
	else if (player_number == 1) {
    	dotprod_share = dotprod_share.lazy_add(x[0] * y[0] + x[1] * y[0] + x[0] * y[1]);
	}
	else {
		dotprod_share = dotprod_share.lazy_add(x[0] * y[1] + x[1] * y[0]);
	}
}

template<class T>
inline void SemiRingProtocol<T>::next_dotprod()
{

	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In next_dotprod()" << endl;
    }

    dotprod_share.normalize();
	int n = -1;
    // prepare_reshare(dotprod_share);

	int player_number = P.my_real_num();
	typename T::value_type tmp, tmp2;

	if (player_number == 0) {
		for (int i = 0; i < 2; i ++) {
			tmp.randomize(shared_prngs[i], n);
			add_shares.push_back(tmp);
		}

		tmp.randomize(shared_prngs[0], n);
		tmp = dotprod_share - tmp;

		// os[0].reset_write_head();		// I always forgot why I do this. But if don't, the result is wrong
		
		tmp.pack(os[0], n);
		// P.send_relative(-1, os[0]);

	}
	else if (player_number == 1) {
		
		tmp.randomize(shared_prngs[1], n);
		add_shares.push_back(tmp);
		tmp2 = tmp;

		tmp.randomize(shared_prngs[1], n);
		tmp = dotprod_share + tmp - tmp2;
		add_shares.push_back(tmp);

		tmp.pack(os[0], n);

	}

	else {
		tmp.randomize(shared_prngs[0], n);
		tmp_shares.push_back(tmp);
		tmp2 = tmp;

		// P.receive_relative(1, os[1]);
		// tmp.unpack(os[1], n);

		// os[1].reset_write_head();	// I always forgot why I do this. But if don't, the result is wrong

		tmp = dotprod_share - tmp2;
		tmp_shares.push_back(tmp);
		this->total_recv ++;
		signal();
		
		// tmp.pack(os[0], n);
	}
	


    dotprod_share.assign_zero();
}

template<class T>
inline T SemiRingProtocol<T>::finalize_dotprod(int length)
{

	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In finalize_dotprod()" << endl;
    }

    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

template<class T>
T SemiRingProtocol<T>::get_random() {
	T res;
	for (int i = 0; i < 2; i++) {
		res[i].randomize(shared_prngs[i]);
	}
	return res;
}

template<class T>
template<class U>
void SemiRingProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
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

template<class T>
template<class U>
void SemiRingProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void SemiRingProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{

	if (TRUNC_LOG_LEVEL & TRUNC_PROCESS) {
		cout << "In trunc_pr()" << endl;
	}
	if (TRUNC_LOG_LEVEL & TRUNC_DETAIL) {
		cout << "regs: ";
		for (auto i : regs) {
			cout << i << " ";
		}
		cout << endl << size << endl;
	}

    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

#endif