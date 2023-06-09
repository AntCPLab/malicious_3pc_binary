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
    
    sid = Mersenne::randomize(global_prng);

    check_prngs.resize(OnlineOptions::singleton.max_status);

    for (auto &prngs: check_prngs) {
        prngs[0].SetSeed(shared_prngs[0]);
        prngs[1].SetSeed(shared_prngs[1]);
    }

    for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
        #ifdef TIMING
        check_threads.push_back(std::thread(&Malicious3PCProtocol<T>::thread_handler, this, i));
        verify_threads.push_back(std::thread(&Malicious3PCProtocol<T>::verify_thread_handler, this, i));
        #else
        check_threads.push_back(std::thread(&Malicious3PCProtocol<T>::thread_handler, this));
        verify_threads.push_back(std::thread(&Malicious3PCProtocol<T>::verify_thread_handler, this));
        #endif
    }

    this->local_counter = 0;
    this->status_counter = 0;
    this->status_pointer = 0;

    wait_size.set_target(OnlineOptions::singleton.max_status);

    idx_input = idx_result = idx_rho = 0;
    // works for binary_batch_size % BLOCK_SIZE = 0
    // share_tuple_block_size = OnlineOptions::singleton.binary_batch_size * OnlineOptions::singleton.max_status * ZOOM_RATE / BLOCK_SIZE; // key bug
    size_t total_batch_size = OnlineOptions::singleton.binary_batch_size * OnlineOptions::singleton.max_status;
    share_tuple_block_size = (MAX_LAYER_SIZE > total_batch_size ? MAX_LAYER_SIZE : total_batch_size) * ZOOM_RATE / BLOCK_SIZE;

    // cout << "Using tuple size: " << share_tuple_block_size << endl;

    share_tuple_blocks = new ShareTupleBlock[share_tuple_block_size];

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

    // for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
    //     cv.push(-1);
    // }
    
    // for (auto &each_thread: check_threads) {
    //     each_thread.join();
    // }

    // if (local_counter > 0) {
    //     // cout << "local_counter = " << local_counter << endl;
    //     Check_one(status_pointer, local_counter);
    //     status_counter ++;
    // }

    // if (status_counter > 0) {
    //     // cout << "status_counter = " << status_counter << endl;
    //     verify();
    // }
    
}

#ifdef TIMING
template <class T>
void Malicious3PCProtocol<T>::thread_handler(int tid) {
    ofstream outfile;
    outfile.open("logs/Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));
    outfile << "thread_handler starts at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    auto cp0 = std::chrono::high_resolution_clock::now();
    
    int _ = -1;
    while (true) { 
        if (!cv.pop_dont_stop(_)) {
            continue;
        }

        if (_ == -1) {
            outfile << "breaking thread_handler loop... tid: " << tid << endl;
            
            break;
        }

        outfile << "calling Check_one " << endl;
        Check_one(_);
        
    }
    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "thread running time " << (cp1 - cp0).count() / 1e6 << "ms." << endl;
    outfile << "verify_thread_handler ends at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
    
    return ;
}
#else
template <class T>
void Malicious3PCProtocol<T>::thread_handler() {

    int _ = -1;
    while (true) { 
        if (!cv.pop_dont_stop(_)) {
            continue;
        }

        if (_ == -1) {            
            break;
        }

        // auto cp0 = std::chrono::high_resolution_clock::now();
        Check_one(_);
        // auto cp1 = std::chrono::high_resolution_clock::now();
        // cout << "Check_one uses " << (cp1 - cp0).count() / 1e6 << "ms." << endl;
    
        
    }
    return ;
}
#endif

template <class T>
void Malicious3PCProtocol<T>::verify_part1(int prev_number, int my_number) {
    DZKProof proof;
    verify_lock.lock();
    int i = verify_index ++;
    proof.unpack(proof_os[1]);
    verify_lock.unlock();

    size_t sz = status_queue[i].sz;
    // int k = OnlineOptions::singleton.k_size;
    // int cnt = log(4 * sz) / log(k) + 1;

    #ifdef TIMING
    auto cp1 = std::chrono::high_resolution_clock::now();
    #endif

    vermsgs[i] = _gen_vermsg(proof, status_queue[i].node_id, status_queue[i].mask_ss_prev, sz, sid, prev_number, my_number);

    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    cout << "Gen_vermsg uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;
    #endif

    ++ verify_tag;
    
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

    size_t sz = status_queue[i].sz;
    // int k = OnlineOptions::singleton.k_size;

    // int cnt = log(4 * sz) / log(k) + 1;
    #ifdef TIMING
    auto cp1 = std::chrono::high_resolution_clock::now();
    #endif

    bool res = _verify(proof, received_vermsg, status_queue[i].node_id, status_queue[i].mask_ss_next, sz, sid, next_number, my_number);
    
    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    cout << "Verify uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;
    #endif

    if (!res) {
        check_passed = false;
    }

    ++ verify_tag;
    
}

#ifdef TIMING
template <class T>
void Malicious3PCProtocol<T>::verify_thread_handler(int tid) {
    ofstream outfile;
    outfile.open("logs/Verify_Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));
    outfile << "verify_thread_handler starts at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;

    auto cp0 = std::chrono::high_resolution_clock::now();

    u_char data = 0;
    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    while (true) { 
        if (!verify_queue.pop_dont_stop(data)) {
            continue;
        }

        if (data == 0) {
            outfile << "Exit verify thread" << endl;
            break;
        }

        else if (data == 1) {
            outfile << "calling verify_part1" << endl;
            verify_part1(prev_number, my_number);
        }

        else if (data == 2) {
            outfile << "calling verify_part2" << endl;
            verify_part2(next_number, my_number);
        }
    }
    auto cp1 = std::chrono::high_resolution_clock::now();
    outfile << "thread running time " << (cp1 - cp0).count() / 1e6 << "ms." << endl;
    outfile << "verify_thread_handler ends at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
}
#else
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
#endif

template <class T>
void Malicious3PCProtocol<T>::verify() {

    // cout << "in Malicious3PCProtocol::verify, this->bit_counter: " << this->bit_counter << endl;
    // cout << "in Malicious3PCProtocol::verify, this->bit_counter_aligned: " << this->bit_counter_aligned << endl;

    // ofstream outfile;
    // outfile.open("logs/Verify_" + to_string(P.my_real_num()), ios::app);
    
    if (status_counter == 0) {
        return ;
    }

    for (auto& o : proof_os) {
        o.clear();
    }

    for (auto& o : vermsg_os) {
        o.clear();
    }

    size_t size = status_counter;

    // outfile << "Verify with size " << size << endl;

    verify_index = 0;
    check_passed = true;
    verify_tag.reset();
    verify_tag.set_target(size);

    // auto cp0 = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < size; i ++) {
        DZKProof proof = status_queue[i].proof;   
        proof.pack(proof_os[0]);
    }

    this->check_comm += proof_os[0].get_length();
    P.pass_around(proof_os[0], proof_os[1], 1);

    // auto cp1 = std::chrono::high_resolution_clock::now();
    // outfile << "Exchange proof1 uses " << (cp1 - cp0).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        verify_queue.push(1);
    }

    verify_tag.wait();
    verify_tag.reset();
    verify_index = 0;

    // auto cp2 = std::chrono::high_resolution_clock::now();
    // outfile << "Gen vermsg uses " << (cp2 - cp1).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        vermsgs[i].pack(vermsg_os[0]);
    }

    proof_os[1].reset_write_head();

    this->check_comm += proof_os[0].get_length();
    this->check_comm += vermsg_os[0].get_length();
  
    P.pass_around(proof_os[0], proof_os[1], -1);
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);

    // auto cp3 = std::chrono::high_resolution_clock::now();
    // outfile << "Exchange vermsg uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;

    for (size_t i = 0; i < size; i ++) {
        verify_queue.push(2);
    }

    verify_tag.wait();
    // if (!check_passed) {
    //     throw mac_fail("Check failed");
    //     // cout << "Check failed" << endl;
    // }

    // auto cp4 = std::chrono::high_resolution_clock::now();
    // outfile << "Verify uses " << (cp4 - cp3).count() / 1e6 << "ms." << endl;

    status_counter = 0;
    wait_size.reset();
}

template <class T>
void Malicious3PCProtocol<T>::Check_one(size_t node_id, int size) {

    // ofstream outfile;
    // outfile.open("logs/CheckOne_" + to_string(P.my_real_num()), ios::app);

    // outfile << "Entering Check_one, node_id = " << node_id << endl;

    // auto cp0 = std::chrono::high_resolution_clock::now();

    // cout << "in Check_one" << node_id << endl;

    if (size == 0)  return ;
    size_t ms = OnlineOptions::singleton.max_status;

    // size_t start = (node_id % (ZOOM_RATE * ms)) * OnlineOptions::singleton.binary_batch_size;
    if (size == -1) size = OnlineOptions::singleton.binary_batch_size;

    size_t sz = size;
    size_t k = OnlineOptions::singleton.k_size;
    size_t k2 = OnlineOptions::singleton.k2_size;
    size_t _T = ((sz - 1) / k + 1) * k;
    size_t s = (_T - 1) / k + 1;
    size_t cnt = log(4 * s) / log(k2) + 3;

    #ifdef DEBUG_OURS_CORRECTNESS_SF
        cout << "cnt in Protocol: " << cnt << endl;
    #endif

    // outfile << "Check one with size " << sz << endl; 

    Field **masks, **mask_ss_next, **mask_ss_prev;

    masks = new Field*[cnt];
    mask_ss_next = new Field*[cnt];
    mask_ss_prev = new Field*[cnt];

    masks[0] = new Field[2 * k - 1];
    mask_ss_next[0] = new Field[2 * k - 1];
    mask_ss_prev[0] = new Field[2 * k - 1];

    #ifdef DEBUG_OURS_CORRECTNESS
        for (int j = 0; j < 2 * k - 1; j ++) {
            mask_ss_next[0][j] = 0;
            mask_ss_prev[0][j] = 0;
            masks[0][j] = 0;
        }
        
        for (int i = 1; i < cnt; i++) {
            masks[i] = new Field[2 * k - 1];
            mask_ss_next[i] = new Field[2 * k - 1];
            mask_ss_prev[i] = new Field[2 * k - 1];

            for (int j = 0; j < 2 * k - 1; j ++) {
                mask_ss_next[i][j] = 0;
                mask_ss_prev[i][j] = 0;
                masks[i][j] = 0;
            }
        }
    #else
        for (size_t j = 0; j < 2 * k - 1; j ++) {
            mask_ss_next[0][j] = Mersenne::randomize(check_prngs[node_id % ms][1]);
            mask_ss_prev[0][j] = Mersenne::randomize(check_prngs[node_id % ms][0]);
            masks[0][j] = Mersenne::add(mask_ss_next[0][j], mask_ss_prev[0][j]);
        }
        
        for (size_t i = 1; i < cnt; i++) {
            masks[i] = new Field[2 * k2 - 1];
            mask_ss_next[i] = new Field[2 * k2 - 1];
            mask_ss_prev[i] = new Field[2 * k2 - 1];

            for (size_t j = 0; j < 2 * k2 - 1; j ++) {
                mask_ss_next[i][j] = Mersenne::randomize(check_prngs[node_id % ms][1]);
                mask_ss_prev[i][j] = Mersenne::randomize(check_prngs[node_id % ms][0]);
                masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
            }
        }
    #endif

    #ifdef TIMING
    auto cp2 = std::chrono::high_resolution_clock::now();
    #endif
    // cout << "Prepare data uses " << (cp2 - cp1_5).count() / 1e6 << "ms." << endl;


    // outfile << "in Check_one, calling prove" << endl;
    // DZKProof proof = _prove(input_left, input_right, masks, sz, k, sid, global_prng);
    DZKProof proof = _prove(node_id, masks, sz, sid);

    #ifdef TIMING
    auto cp3 = std::chrono::high_resolution_clock::now();

    // outfile << "Prove uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;
    cout << "Prove uses " << (cp3 - cp2).count() / 1e6 << "ms." << endl;
    #endif

    // outfile << "in Check_one, pushing status_queue, ID: " << node_id << endl;
    status_queue[node_id % ms] = StatusData(proof,
                                       node_id,
                                       mask_ss_next,
                                       mask_ss_prev,
                                       sz);

    // outfile << "in Check_one, ++wait_size" << endl;
    ++wait_size;
    // outfile << "in Check_one, after ++wait_size" << endl;

    // outfile << "Finish check" << endl;
    
}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    
    typename T::value_type add_share = x.local_mul(y);

    share_tuple_blocks[idx_input].input1 = ShareTypeBlock(x[0].get(), x[1].get());
    share_tuple_blocks[idx_input].input2 = ShareTypeBlock(y[0].get(), y[1].get());
    idx_input ++;
    if (idx_input == share_tuple_block_size) {
        idx_input = 0;
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
    

    share_tuple_blocks[idx_rho].rho = ShareTypeBlock(tmp[0].get(), tmp[1].get());
    idx_rho ++;
    if (idx_rho == share_tuple_block_size) {
        idx_rho = 0;
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
    int this_size = (n == -1 ? T::value_type::length() : n);

    this->counter++;
    this->bit_counter += this_size;
    // this->bit_counter_aligned += T::value_type::length();

    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    // cout << "n: " << n << ", this_size: " << this_size << endl;
    // if (this_size != T::value_type::length()) {
    //     cout << "n: " << n << ", this_size: " << this_size << endl;
    // }

    // if (n == 1) {
    //     cout << "n == 1, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // } else if (n == 2) {
    //     cout << "n == 2, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // } else if (n == 11) {
    //     cout << "n == 11, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // } else if (n == 21) {
    //     cout << "n == 21, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // } else if (n == 52) {
    //     cout << "n == 52, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // } else if (n == 63) {
    //     cout << "n == 63, result[0].get(): " << result[0].get() << endl;
    //     // cout << "T: " << typeid(T).name() << endl;
    // }

    share_tuple_blocks[idx_result].result = ShareTypeBlock(result[0].get(), result[1].get());

    #ifdef DEBUG_OURS_CORRECTNESS
        // x_i * y_i + z_i + rho_i + rho_{i-1}
        ShareTupleBlock tb = share_tuple_blocks[idx_result];
        long z_res = ((tb.input1.first & (tb.input2.first ^ tb.input2.second)) ^ (tb.input2.first & tb.input1.second)) ^ tb.rho.first ^ tb.rho.second;
        
        cout << "in finalize_mul, z_res: " << z_res << ", z_i: " << tb.result.first << endl;
    #endif

    idx_result ++;
    if (idx_result == share_tuple_block_size) {
        idx_result = 0;
    }
    
    // this->local_counter += this_size;
    // TODO: optimize
    this->local_counter += T::value_type::length(); 
    
    // auto start = std::chrono::high_resolution_clock::now();
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
    // auto end = std::chrono::high_resolution_clock::now();
    // cout << "verify uses: " << (end - start).count() / 1e6 << " ms" << endl;
    // cout << "verify() once" << endl;
    
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
    dotprod_share = 0;
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
    dotprod_share = 0;
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