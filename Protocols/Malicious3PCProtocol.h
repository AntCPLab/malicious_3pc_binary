#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_H_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_H_

#include "Replicated.h"
#include "BinaryCheck.h"
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

struct StatusData {
    DZKProof proof;
    size_t node_id;
    Field **mask_ss_prev, **mask_ss_next;
    size_t sz;

    StatusData() {}
    StatusData(DZKProof proof, size_t node_id, Field **mask_ss_prev, Field **mask_ss_next, size_t sz) : 
        proof(proof), node_id(node_id), mask_ss_prev(mask_ss_prev), mask_ss_next(mask_ss_next), sz(sz) {}
    
};

struct ShareTupleBlock {
public:
    ShareTypeBlock input1, input2, result, rho;

    ShareTupleBlock(): input1(), input2(), result(), rho() {}
};

/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */
template<class T>
class Malicious3PCProtocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef Malicious3PCProtocol This;

    ShareTupleBlock *share_tuple_blocks;
    size_t idx_input, idx_rho, idx_result;
    size_t share_tuple_block_size;
    const size_t ZOOM_RATE = 2;

    size_t MAX_LAYER_SIZE = 64000000;

    const Field two_inverse = Mersenne::inverse(2);
    const Field neg_one = Mersenne::PR - 1;
    const Field neg_two = Mersenne::PR - 2;
    const Field neg_two_inverse = Mersenne::neg(two_inverse);

    StatusData *status_queue;
    vector<typename T::open_type> opened;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    std::mutex check_lock;
    size_t check_id;

    WaitQueue<int> cv;

    size_t local_counter, status_counter, status_pointer;
    WaitSize wait_size;
    Field sid;

    vector<std::thread> check_threads, verify_threads;

    array<octetStream, 2> proof_os, vermsg_os;
    size_t verify_index;
    mutex verify_lock;
    VerMsg *vermsgs;
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

    Malicious3PCProtocol(Player& P);
    Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs);
    ~Malicious3PCProtocol() {

        for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
            cv.push(-1);
        }
        
        for (auto &each_thread: check_threads) {
            each_thread.join();
        }

        if (local_counter > 0) {
            // cout << "local_counter = " << local_counter << endl;
            // cout << "this->bit_counter_aligned = " << this->bit_counter_aligned << endl;
            // cout << "this->bit_counter = " << this->bit_counter << endl;
            Check_one(status_pointer, local_counter);
            status_counter ++;
        }

        if (status_counter > 0) {
            cout << "status_counter = " << status_counter << endl;
            verify();
        }
        
        for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
            // cout << "in ~Malicious3PCProtocol, pushing false in cv" << endl;
            verify_queue.push(0);
        }

        cout << "Destroying threads." << endl;
        for (auto &each_thread: verify_threads) {
            each_thread.join();
        }

        cout << "Destroyed." << endl;

        if (!check_passed) {
            // throw mac_fail("Check failed");
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
        
    Malicious3PCProtocol branch() {
        return {P, shared_prngs};
        // return {P, shared_prngs, check_prngs};
    }

    DZKProof _prove(
        size_t node_id,
        Field** masks,
        size_t batch_size, 
        Field sid
    );

    VerMsg _gen_vermsg(
        DZKProof proof, 
        size_t node_id,
        Field** masks_ss,
        size_t batch_size, 
        Field sid,
        size_t prover_ID,
        size_t party_ID
    );

    bool _verify(
        DZKProof proof, 
        VerMsg other_vermsg, 
        size_t node_id,
        Field** masks_ss,
        size_t batch_size, 
        Field sid,
        size_t prover_ID,
        size_t party_ID
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

    // void maybe_check();
    size_t get_n_relevant_players() { return P.num_players() - 1; }

    void verify_part1(int prev_number, int my_number);
    void verify_part2(int next_number, int my_number);

};

#endif /* PROTOCOLS_MALICIOUS3PCPROTOCOL_H_ */