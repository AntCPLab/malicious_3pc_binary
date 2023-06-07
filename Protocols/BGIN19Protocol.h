#ifndef PROTOCOLS_BGIN19PROTOCOL_H_
#define PROTOCOLS_BGIN19PROTOCOL_H_

#include "Replicated.h"
#include "BGIN19BinaryCheck.h"
#include "Processor/Data_Files.h"

#include "queue"
#include "SafeQueue.h"
#include <thread>
#include <fstream>
#include <chrono>

#define USE_THREAD

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;

struct BGIN19StatusData {
    BGIN19DZKProof proof;
    size_t node_id;
    BGIN19Field **mask_ss_prev, **mask_ss_next;
    size_t sz;

    BGIN19StatusData() {}
    BGIN19StatusData(BGIN19DZKProof proof, size_t node_id, BGIN19Field **mask_ss_prev, BGIN19Field **mask_ss_next, size_t sz) : 
        proof(proof), node_id(node_id), mask_ss_prev(mask_ss_prev), mask_ss_next(mask_ss_next), sz(sz) {}
    
};

struct BGIN19ShareTupleBlock {
public:
    ShareTypeBlock input1, input2, result, rho;

    BGIN19ShareTupleBlock(): input1(), input2(), result(), rho() {}
};

/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */
template<class T>
class BGIN19Protocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef BGIN19Protocol This;

    BGIN19ShareTupleBlock *share_tuple_blocks;
    size_t idx_input, idx_rho, idx_result;
    size_t share_tuple_block_size;
    const size_t ZOOM_RATE = 2;

    size_t MAX_LAYER_SIZE = 64000000; // 6400w

    BGIN19StatusData *status_queue;
    vector<typename T::open_type> opened;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    std::mutex check_lock;
    size_t check_id;

    WaitQueue<int> cv;

    size_t local_counter, status_counter, status_pointer;
    WaitSize wait_size;
    BGIN19Field sid;

    vector<std::thread> check_threads, verify_threads;

    array<octetStream, 2> proof_os, vermsg_os;
    size_t verify_index;
    mutex verify_lock;
    BGIN19VerMsg *vermsgs;
    WaitQueue<u_char> verify_queue;
    WaitSize verify_tag;
    bool check_passed;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

public:

    static const bool uses_triples = false;

    array<PRNG, 2> shared_prngs;
    vector<array<PRNG, 2> > check_prngs;

    PRNG global_prng;

    Player& P;

    BGIN19Protocol(Player& P);
    BGIN19Protocol(Player& P, array<PRNG, 2>& prngs);
    ~BGIN19Protocol() {

#ifdef DEBUG_BGIN19
    cout << "in ~BGIN19Protocol" << endl;
#endif
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
        
        for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
            // cout << "in ~BGIN19Protocol, pushing false in cv" << endl;
            verify_queue.push(0);
        }

        cout << "Destroying threads." << endl;
        for (auto &each_thread: verify_threads) {
            each_thread.join();
        }

        cout << "Destroyed." << endl;

        if (!check_passed) {
            cout << "Check failed" << endl;
        }

        // this->print_debug_info("Binary Part");
        cout << "End Mal3pc at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
    }
    

    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share = 0;
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
    T dotprod_finalize_mul(int n = -1);
    T finalize_dotprod(int length);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    T get_random();
    void randoms(T& res, int n_bits);

    void start_exchange();
    void stop_exchange();
        
    BGIN19Protocol branch() {
        return {P, shared_prngs};
        // return {P, shared_prngs, check_prngs};
    }

    BGIN19DZKProof _prove(
        size_t node_id,
        BGIN19Field** masks,
        size_t batch_size, 
        BGIN19Field sid,
        PRNG prng
    );

    BGIN19VerMsg _gen_vermsg(
        BGIN19DZKProof proof, 
        size_t node_id,
        BGIN19Field** masks_ss,
        size_t batch_size, 
        BGIN19Field sid,
        size_t prover_ID,
        size_t party_ID,
        PRNG prng
    );

    bool _verify(
        BGIN19DZKProof proof, 
        BGIN19VerMsg other_vermsg, 
        size_t node_id,
        BGIN19Field** masks_ss,
        size_t batch_size, 
        BGIN19Field sid,
        size_t prover_ID,
        size_t party_ID,
        PRNG prng
    );

    void check();
    void finalize_check();
    void Check_one(size_t node_id, int size = -1);
    void verify();
    #ifdef TIMING
    void thread_handler(size_t tid);
    void verify_thread_handler(size_t tid);
    #else
    void thread_handler();
    void verify_thread_handler();
    #endif

    size_t get_n_relevant_players() { return P.num_players() - 1; }
    void verify_part1(int prev_number, int my_number);
    void verify_part2(int next_number, int my_number);

};

#endif /* PROTOCOLS_BGIN19PROTOCOL_H_ */