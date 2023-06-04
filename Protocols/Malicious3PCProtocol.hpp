#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"

#include "Replicated.h"
#include "Tools/octetStream.h"
#include "Tools/time-func.h"

#include <chrono>
#include <string.h>
#include <fstream>

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : P(P) {

    cout << "Start Mal3pc at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    assert(P.num_players() == 3);
    assert(OnlineOptions::singleton.thread_number > 0);
    assert(OnlineOptions::singleton.max_status > 0);

	if (not P.is_encrypted())
		insecure("unencrypted communication");

    status_queue = new StatusData[OnlineOptions::singleton.max_status];
    
    shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.send_relative(1, os);
	P.receive_relative(-1, os);
	shared_prngs[1].SetSeed(os.get_data());

    os.reset_write_head();
    if (P.my_real_num() == 0) {
        global_prng.ReSeed();
        os.append(global_prng.get_seed(), SEED_SIZE);
        P.send_all(os);
    }
    else {
        P.receive_player(0, os);
        global_prng.SetSeed(os.get_data());
    }
    
    check_prngs.resize(OnlineOptions::singleton.max_status);

    for (auto &prngs: check_prngs) {
        prngs[0].SetSeed(shared_prngs[0]);
        prngs[1].SetSeed(shared_prngs[1]);
    }

    for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
        check_threads.push_back(std::thread(&Malicious3PCProtocol<T>::thread_handler, this, i));
        verify_threads.push_back(std::thread(&Malicious3PCProtocol<T>::verify_thread_handler, this));
    }

    this->local_counter = 0;
    this->status_counter = 0;
    this->status_pointer = 0;

    wait_size.set_target(OnlineOptions::singleton.max_status);

    idx_input = idx_result = idx_rho = 0;
    share_tuple_size = OnlineOptions::singleton.binary_batch_size * OnlineOptions::singleton.max_status * ZOOM_RATE;
    
    cout << "Using tuple size: " << share_tuple_size << endl;

    input1 = new ShareType[share_tuple_size];
    input2 = new ShareType[share_tuple_size];
    rhos = new ShareType[share_tuple_size];
    results = new ShareType[share_tuple_size];

    vermsgs = new VerMsg[OnlineOptions::singleton.max_status];
}

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++) {
        shared_prngs[i].SetSeed(prngs[i]);
    }

    for (auto &prngs: check_prngs) {
        prngs[0].SetSeed(shared_prngs[0]);
        prngs[1].SetSeed(shared_prngs[1]);
    }
}

template <class T>
void Malicious3PCProtocol<T>::check() {

}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{
	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();

    // cout << "local_counter: " << local_counter << endl;
}

template <class T>
void Malicious3PCProtocol<T>::finalize_check() {

    // cout << "in finalize_check" << endl;

    for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
        cv.push(-1);
    }
    
    for (auto &each_thread: check_threads) {
        each_thread.join();
    }

    if (local_counter > 0) {
        // cout << "local_counter = " << local_counter << endl;
        Check_one(status_pointer, local_counter);
        status_counter ++;
    }

    if (status_counter > 0) {
        // cout << "status_counter = " << status_counter << endl;
        verify();
    }
    
}

template <class T>
void Malicious3PCProtocol<T>::thread_handler(int tid) {
    // ofstream outfile;
    // outfile.open("logs/Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));

    
    int _ = -1;
    while (true) { 
        if (!cv.pop_dont_stop(_)) {
            continue;
        }
        // outfile << "value _: " << _ << endl;

        if (_ == -1) {
            // outfile << "breaking thread_handler loop... tid: " << tid << endl;
            
            break;
        }

        Check_one(_);
        
    }
    return ;
}

template <class T>
void Malicious3PCProtocol<T>::verify_part1(int prev_number, int my_number) {
    DZKProof proof;
    verify_lock.lock();
    int i = verify_index ++;
    proof.unpack(proof_os[1]);
    verify_lock.unlock();

    uint64_t **input_shared_next = status_queue[i].input_shared_next;
    uint64_t **mask_ss_prev = status_queue[i].mask_ss_prev;
    int sz = status_queue[i].sz;
    int k = OnlineOptions::singleton.k_size;
    int cnt = log(4 * sz) / log(k) + 1;

    vermsgs[i] = gen_vermsg(proof, input_shared_next, sz, k, mask_ss_prev, prev_number, my_number);

    ++ verify_tag;

    for (int j = 0; j < k; j ++) {
        delete[] input_shared_next[j];
    }
    delete[] input_shared_next;

    for (int j = 0; j < cnt; j ++) {
        delete[] mask_ss_prev[j];
    }
    delete[] mask_ss_prev;
    
}
template <class T>
void Malicious3PCProtocol<T>::verify_part2(int next_number, int my_number) {
    
    VerMsg received_vermsg;
    DZKProof proof;
    
    verify_lock.lock();
    received_vermsg.unpack(vermsg_os[1]);
    proof.unpack(proof_os[1]);
    int i = verify_index ++;
    verify_lock.unlock();

    uint64_t **input_shared_prev = status_queue[i].input_shared_prev;
    uint64_t **mask_ss_next = status_queue[i].mask_ss_next;

    int sz = status_queue[i].sz;
    int k = OnlineOptions::singleton.k_size;

    int cnt = log(4 * sz) / log(k) + 1;

    bool res = _verify(proof, input_shared_prev, received_vermsg, sz, k, mask_ss_next, next_number, my_number);   
    if (!res) {
        check_passed = false;
    }

    ++ verify_tag;

    for (int j = 0; j < k; j ++) {
        delete[] input_shared_prev[j];
    }
    delete[] input_shared_prev;

    for (int j = 0; j < cnt; j ++) {
        delete[] mask_ss_next[j];
    }
    delete[] mask_ss_next;

    

}

template <class T>
void Malicious3PCProtocol<T>::verify_thread_handler() {

    u_char data = 0;
    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    while (true) { 
        if (!verify_queue.pop_dont_stop(data)) {
            continue;
        }

        if (data == 0) {
            // cout << "Exit verify thread" << endl;
            break;
        }

        else if (data == 1) {
            verify_part1(prev_number, my_number);
        }

        else if (data == 2) {
            verify_part2(next_number, my_number);
        }
    }
}


template <class T>
void Malicious3PCProtocol<T>::verify() {

    // cout << "in Malicious3PCProtocol::verify, this->bit_counter: " << this->bit_counter << endl;

    ofstream outfile;
    outfile.open("logs/Verify_" + to_string(P.my_real_num()), ios::app);
    
    if (status_counter == 0) {
        return ;
    }

    for (auto& o : proof_os) {
        o.clear();
    }

    for (auto& o : vermsg_os) {
        o.clear();
    }

    int size = status_counter;

    outfile << "Verify with size " << size << endl;

    verify_index = 0;
    check_passed = true;
    verify_tag.reset();
    verify_tag.set_target(size);

    auto cp0 = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < size; i ++) {
        DZKProof proof = status_queue[i].proof;   
        proof.pack(proof_os[0]);
    }

    this->check_comm += proof_os[0].get_length();
    P.pass_around(proof_os[0], proof_os[1], 1);

    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "Exchange proof1 uses " << (cp1 - cp0).count() / 1e6 << "ms." << endl;

    for (int i = 0; i < size; i ++) {
        verify_queue.push(1);
    }

    verify_tag.wait();
    verify_tag.reset();
    verify_index = 0;

    auto cp2 = std::chrono::high_resolution_clock::now();
    outfile << "Gen vermsg uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;

    for (int i = 0; i < size; i ++) {
        vermsgs[i].pack(vermsg_os[0]);
    }

    proof_os[1].reset_write_head();

    this->check_comm += proof_os[0].get_length();
    this->check_comm += vermsg_os[0].get_length();
  
    P.pass_around(proof_os[0], proof_os[1], -1);
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);

    auto cp3 = std::chrono::high_resolution_clock::now();
    outfile << "Exchange vermsg uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;

    for (int i = 0; i < size; i ++) {
        verify_queue.push(2);
    }

    verify_tag.wait();
    if (!check_passed) {
        throw mac_fail("ZKP check failed");
    }

    auto cp4 = std::chrono::high_resolution_clock::now();
    outfile << "Verify uses " << (cp4 - cp3).count() / 1e6 << "ms." << endl;

    status_counter = 0;
    wait_size.reset();

}

template <class T>
void Malicious3PCProtocol<T>::Check_one(int node_id, int size) {

    ofstream outfile;
    outfile.open("logs/CheckOne_" + to_string(P.my_real_num()), ios::app);

    // outfile << "Entering Check_one, node_id = " << node_id << endl;

    auto cp0 = std::chrono::high_resolution_clock::now();

    if (size == 0)  return ;
    int ms = OnlineOptions::singleton.max_status;

    size_t start = (node_id % (ZOOM_RATE * ms)) * OnlineOptions::singleton.binary_batch_size;
    if (size == -1) size = OnlineOptions::singleton.binary_batch_size;

    int sz = size;
    int k = OnlineOptions::singleton.k_size, cols = (sz - 1) / k + 1;
    int cnt = log(4 * sz) / log(k) + 1;

    outfile << "Check one with size " << sz << endl; 

    uint64_t **masks, **mask_ss_next, **mask_ss_prev;

    masks = new uint64_t*[cnt];
    mask_ss_next = new uint64_t*[cnt];
    mask_ss_prev = new uint64_t*[cnt];
    
    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2 * k - 1];
        mask_ss_next[i] = new uint64_t[2 * k - 1];
        mask_ss_prev[i] = new uint64_t[2 * k - 1];

        for (int j = 0; j < 2 * k - 1; j ++) {
            mask_ss_next[i][j] = check_prngs[node_id % ms][1].get_word() & Mersenne::PR;
            mask_ss_prev[i][j] = check_prngs[node_id % ms][0].get_word() & Mersenne::PR;
            masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
        }
    }

    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "PRNG uses " << (cp1 - cp0).count() / 1e6 << "ms." << endl;

    ShareType *_input1, *_input2, *_results, *_rhos;
    _input1 = new ShareType[sz];
    _input2 = new ShareType[sz];
    _results = new ShareType[sz];
    _rhos = new ShareType[sz];

    memcpy(_input1, input1 + start, sizeof(ShareType) * sz);
    memcpy(_input2, input2 + start, sizeof(ShareType) * sz);
    memcpy(_results, results + start, sizeof(ShareType) * sz);
    memcpy(_rhos, rhos + start, sizeof(ShareType) * sz);

    auto cp1_5 = std::chrono::high_resolution_clock::now();
    outfile << "Memcpy uses " << (cp1_5 - cp1).count() / 1e6 << "ms." << endl;


    int temp_pointer = 0;
    uint64_t **input_left, **input_right, **input_shared_next, **input_shared_prev;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_shared_next = new uint64_t*[k];
    input_shared_prev = new uint64_t*[k];

    uint64_t neg_one = Mersenne::PR - 1;
    uint64_t neg_two = Mersenne::PR - 2;
    uint64_t neg_two_inverse = Mersenne::neg(two_inverse);
    
    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 4];
        input_right[i] = new uint64_t[cols * 4];
        input_shared_next[i] = new uint64_t[cols * 4];
        input_shared_prev[i] = new uint64_t[cols * 4];
    
        // memset(input_left[i], 0, sizeof(uint64_t) * cols * 4);
        // memset(input_right[i], 0, sizeof(uint64_t) * cols * 4);
        // memset(input_shared_next[i], 0, sizeof(uint64_t) * cols * 4);
        // memset(input_shared_prev[i], 0, sizeof(uint64_t) * cols * 4);
        
        for (int j = 0; j < cols; j++) {

            ShareType x, y, z, rho;

            if (temp_pointer >= sz) {
                input_left[i][j * 4] = 0;
                input_left[i][j * 4 + 1] = 0;
                input_left[i][j * 4 + 2] = 0;
                input_left[i][j * 4 + 3] = 0;
                input_right[i][j * 4] = 0;
                input_right[i][j * 4 + 1] = 0;
                input_right[i][j * 4 + 2] = 0;
                input_right[i][j * 4 + 3] = 0;
                input_shared_prev[i][j * 4] = 0;
                input_shared_prev[i][j * 4 + 1] = 0;
                input_shared_prev[i][j * 4 + 2] = 0;
                input_shared_prev[i][j * 4 + 3] = 0;
                input_shared_next[i][j * 4] = 0;
                input_shared_next[i][j * 4 + 1] = 0;
                input_shared_next[i][j * 4 + 2] = 0;
                input_shared_next[i][j * 4 + 3] = 0;
                temp_pointer ++;
                continue;
            }

            else {
                x = _input1[temp_pointer];
                y = _input2[temp_pointer];
                z = _results[temp_pointer];
                rho = _rhos[temp_pointer];
            }

            // bool res = (x.first & y.first) ^ (x.second & y.first) ^ (x.first & y.second) ^ rho.first ^ rho.second;
            // if(z.first != res) {
            //     cout << "z.first != ((x.first & y.first) ^ (x.second & y.first) ^ (x.first & y.second) ^ rho.first ^ rho.second, temp_pointer: " << temp_pointer << endl;
            // }

            bool e = z.first ^ (x.first & y.first) ^ rho.first;
            bool f = rho.second;

            uint64_t t1 = e ? neg_one : 1;
            uint64_t t2 = f ? neg_one : 1;

            
            input_left[i][j * 4] = x.first & y.first ? (e ? 2 : neg_two) : 0;
            input_left[i][j * 4 + 1] = y.first ? t1 : 0;
            input_left[i][j * 4 + 2] = x.first ? t1 : 0;
            input_left[i][j * 4 + 3] = e ? two_inverse : neg_two_inverse;

            input_right[i][j * 4] = y.second & x.second ? t2 : 0;
            input_right[i][j * 4 + 1] = x.second ? t2 : 0;
            input_right[i][j * 4 + 2] = y.second ? t2 : 0;
            input_right[i][j * 4 + 3] = t2;

            e = z.second ^ (x.second & y.second) ^ rho.second;
            f = rho.first;

            t1 = e ? neg_one : 1;
            t2 = f ? neg_one : 1;

            input_shared_prev[i][j * 4] = x.second & y.second ? (e ? 2 : neg_two) : 0;
            input_shared_prev[i][j * 4 + 1] = y.second ? t1 : 0;
            input_shared_prev[i][j * 4 + 2] = x.second ? t1 : 0;
            input_shared_prev[i][j * 4 + 3] = e ? two_inverse : neg_two_inverse;
            input_shared_next[i][j * 4] = y.first & x.first ? t2 : 0;
            input_shared_next[i][j * 4 + 1] = x.first ? t2 : 0;
            input_shared_next[i][j * 4 + 2] = y.first ? t2 : 0;
            input_shared_next[i][j * 4 + 3] = t2;

            temp_pointer ++;
        }
    }


    auto cp2 = std::chrono::high_resolution_clock::now();

    outfile << "Prepare uses " << (cp2 - cp1_5).count() / 1e6 << "ms." << endl;
    // outfile << "in Check_one, calling prove" << endl;
    DZKProof dzkproof = prove(input_left, input_right, sz, k, masks);

    auto cp3 = std::chrono::high_resolution_clock::now();

    outfile << "Prove uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;

    // outfile << "in Check_one, pushing status_queue, ID: " << node_id << endl;
    status_queue[node_id % ms] = StatusData(dzkproof,
                                       input_shared_next, 
                                       input_shared_prev, 
                                       mask_ss_next,
                                       mask_ss_prev,
                                       sz);

    // outfile << "in Check_one, ++wait_size" << endl;
    ++wait_size;
    // outfile << "in Check_one, after ++wait_size" << endl;

    for (int i = 0; i < k; i ++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (int i = 0; i < cnt; i ++) {
        delete[] masks[i];
    }

    delete[] masks;

    delete[] _input1;
    delete[] _input2;
    delete[] _results;
    delete[] _rhos;

    // outfile << "Finish check" << endl;
    
}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    
    typename T::value_type add_share = x.local_mul(y);

    int this_size = (n == -1 ? T::value_type::length() : n);

    register long x0 = x[0].get(), x1 = x[1].get();
    register long y0 = y[0].get(), y1 = y[1].get();

    for (register short i = 0; i < this_size; i ++) {
        input1[idx_input] = ShareType((x0 >> i) & 1, (x1 >> i & 1));
        input2[idx_input] = ShareType((y0 >> i) & 1, (y1 >> i & 1));
        idx_input ++;
        if (idx_input == share_tuple_size) {
            idx_input = 0;
        }
    }

    prepare_reshare(add_share, n);
    
}

template<class T>
void Malicious3PCProtocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++) 
        tmp[i].randomize(shared_prngs[i], n);
    
    int this_size = (n == -1 ? T::value_type::length() : n);
    register long rho0 = tmp[0].get(), rho1 = tmp[1].get();

    for (register short i = 0; i < this_size; i ++) {
        rhos[idx_rho] = ShareType((rho0 >> i) & 1, (rho1 >> i & 1));
        idx_rho ++;
        if (idx_rho == share_tuple_size) {
            idx_rho = 0;
        }
    }

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Malicious3PCProtocol<T>::exchange()
{

    if (os[0].get_length() > 0) {
        this->exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }

    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    this->exchange_comm += os[0].get_length();
    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_mul(int n)
{
    this->counter++;
    this->bit_counter += (n == -1 ? T::value_type::length() : n);

    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    int this_size = (n == -1 ? T::value_type::length() : n);
    
    register long z0 = result[0].get(), z1 = result[1].get();

    
    for (register short i = 0; i < this_size; i ++) {
        results[idx_result] = ShareType((z0 >> i) & 1, (z1 >> i & 1));
        idx_result ++;
        if (idx_result == share_tuple_size) {
            idx_result = 0;
        }
    } 
    
    this->local_counter += this_size;
    

    while (local_counter >= (size_t) OnlineOptions::singleton.binary_batch_size) {
        local_counter -= OnlineOptions::singleton.binary_batch_size;     
        
        // cout << "Indexes are: " << idx_input << " " << idx_rho << " " << idx_result << endl;
        
        cv.push(status_pointer);

        status_counter ++;
        status_pointer ++;

        if (status_counter == (size_t) OnlineOptions::singleton.max_status) {
            wait_size.wait();
            verify();
        }
    }
    
    return result;
}

template <class T>
inline T Malicious3PCProtocol<T>::dotprod_finalize_mul(int n) {
    this->counter++;
    
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    return result;
}

template<class T>
inline void Malicious3PCProtocol<T>::init_dotprod()
{
    init_mul();
    dotprod_share.assign_zero();
}

template<class T>
inline void Malicious3PCProtocol<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Malicious3PCProtocol<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_dotprod(int length)
{

    (void) length;
    this->dot_counter++;
    return dotprod_finalize_mul();
}

template<class T>
T Malicious3PCProtocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
    return res;
}

template<class T>
void Malicious3PCProtocol<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
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
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

#endif