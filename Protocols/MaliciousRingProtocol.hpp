#ifndef PROTOCOLS_MALICIOUSRINGPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUSRINGPROTOCOL_HPP_

#include "MaliciousRingProtocol.h"

template <class T>
MaliciousRingProtocol<T>::MaliciousRingProtocol(Player& P) :
    SpdzWise<T>(P), zero_prep(0, zero_usage), zero_proc(zero_output, zero_prep, P)
{
}

template<class T>
void MaliciousRingProtocol<T>::zero_check(check_type t)
{
    int l = T::LENGTH + T::SECURITY;
    vector<zero_check_type> bit_masks(l);
    zero_check_type masked = t;
    zero_prep.buffer_size = l;
    for (int i = 0; i < l; i++)
    {
        bit_masks[i] = zero_prep.get_bit();
        masked += bit_masks[i] << i;
    }
    auto& P = this->P;
    auto opened = zero_output.open(masked, P);
    vector<zero_check_type> bits(l);
    for (int i = 0; i < l; i++)
    {
        auto b = opened.get_bit(i);
        bits[i] = zero_check_type::constant(b, P.my_num()) + bits[i]
                - 2 * b * bits[i];
    }
    while(bits.size() > 1)
    {
        auto& protocol = zero_proc.protocol;
        protocol.init_mul();
        for (int i = bits.size() - 2; i >= 0; i -= 2)
            protocol.prepare_mul(bits[i], bits[i + 1]);
        protocol.exchange();
        int n_mults = bits.size() / 2;
        bits.resize(bits.size() % 2);
        for (int i = 0; i < n_mults; i++)
            bits.push_back(protocol.finalize_mul());
    }
    zero_output.CheckFor(0, {bits[0]}, P);
    zero_output.Check(P);
    zero_proc.protocol.check();
}

template <class T>
void MaliciousRingProtocol<T>::thread_handler() {
	typename T::value_type tmp;

	// cout << "Running new thread" << endl;

	if (os[1].empty())
		P.receive_relative(1, os[1]);

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
void MaliciousRingProtocol<T>::init_mul() {

	if (LOG_LEVEL & SHOW_PROGRESS)
		cout << "Init mul " << time(0) << endl;

	if (T is binary_share) {
		our_check
	}
	else {
		SpdzWiseMC<U<T>>
	}

    for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
	if (P.my_real_num() == 2) {
		PointerVector<typename T::clear> empty;
		swap(empty, tmp_shares);
	}

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
void MaliciousRingProtocol<T>::prepare_mul(const T& x, const T& y, int n) {
	
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
void MaliciousRingProtocol<T>::exchange2() {
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
void MaliciousRingProtocol<T>::exchange1() {
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
void MaliciousRingProtocol<T>::exchange() {

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
inline T MaliciousRingProtocol<T>::finalize_mul(int n) {

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
inline void MaliciousRingProtocol<T>::init_dotprod()
{
	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In init_dotprod()" << endl;
    }
    init_mul();
    dotprod_share.assign_zero();
	
	if (P.my_real_num() == 2) {
		this->recv_running = true;
		this->recv_thread = std::thread(&MaliciousRingProtocol<T>::thread_handler, this);
		this->waiting = false;
	}

	
}

template<class T>
inline void MaliciousRingProtocol<T>::prepare_dotprod(const T& x, const T& y)
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
inline void MaliciousRingProtocol<T>::next_dotprod()
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
inline T MaliciousRingProtocol<T>::finalize_dotprod(int length)
{

	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In finalize_dotprod()" << endl;
    }

    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

#endif