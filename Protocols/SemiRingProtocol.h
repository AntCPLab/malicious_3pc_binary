/*
 * Semi-honest ring protocol
 *
 */

#ifndef PROTOCOLS_SEMIRINGPROTOCOL_H_
#define PROTOCOLS_SEMIRINGPROTOCOL_H_

#define USE_MY_MULTIPLICATION

#include "Protocols/Replicated.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"
#include "Protocols/SemiMC.h"
#include "Tools/random.h"

#include <thread>
#include <mutex>
#include <condition_variable>

#include "Protocols/SafeQueue.h"

// multiplication protocol
template<class T>
class SemiRingProtocol : public ProtocolBase<T>, public ReplicatedBase
{

    typedef ReplicatedBase super;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares;
    typename T::clear dotprod_share;
    PointerVector<typename T::clear> tmp_shares;
    int n_bits;
    int total_recv;
    int dealed;
    volatile bool waiting;
    

    std::thread recv_thread;
    volatile bool recv_running;
    std::mutex mtk;
    condition_variable cv;
    int n_times;

    std::mutex mtk2;
    condition_variable cv2;
    int count2;

    // pthread_mutex_t queue_lock;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

public:
    
    static const bool uses_triples = false;

    SemiRingProtocol() {}
    SemiRingProtocol(Player& P);
    SemiRingProtocol(const ReplicatedBase &other) : 
        ReplicatedBase(other)
    {
    }

    // Init the protocol
    SemiRingProtocol(const SemiRingProtocol<T> &other) : super(other)
    {
        
    }

    ~SemiRingProtocol() {
        if (this->recv_thread.joinable()) {
            this->recv_running = false;
            signal();
            this->recv_thread.join();
        }
    }


    // Public input.
    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
        
        share.is_zero_share = true;
    }

    // prepare next round of multiplications
    void init_mul();

    // schedule multiplication
    void prepare_mul(const T&, const T&, int = -1);

    // execute protocol
    void exchange();
    void exchange1();
    void exchange2();

#ifndef USE_MY_MULTIPLICATION

    void prepare_reshare(const typename T::clear& share, int n = -1);
    void start_exchange();
    void stop_exchange();

#endif

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    // return next product
    T finalize_mul(int = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    // void multiply(vector<T>& products, vector<pair<T, T>>& multiplicands,
    //         int begin, int end, SubProcessor<T>& proc);

    T get_random();

    void thread_handler();

    inline void wait() {
        std::unique_lock<std::mutex> lk(this->mtk);
        if (--this->n_times < 0 and this->recv_running) {
            cv.wait(lk);
        }
    }

    inline void signal() {
        std::unique_lock<std::mutex> lk(this->mtk);
        if (++this->n_times <= 0) {
            cv.notify_one();
        }
    }

    inline void wait2() {
        std::unique_lock<std::mutex> lk(this->mtk2);
        if (--this->count2 < 0) {
            cv2.wait(lk);
        }
    }

    inline void signal2() {
        std::unique_lock<std::mutex> lk(this->mtk2);
        if (++this->count2 <= 0) {
            cv2.notify_one();
        }
    }

};

#endif /* PROTOCOLS_SEMIRINGPROTOCOL_H_ */
