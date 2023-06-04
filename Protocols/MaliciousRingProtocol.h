#ifndef PROTOCOLS_MALICIOUSRINGPROTOCOL_H_
#define PROTOCOLS_MALICIOUSRINGPROTOCOL_H_

#include "SpdzWise.h"
#include "PostSacrifice.h"
#include "PostSacriRepRingShare.h"

template <class T>
class MaliciousRingProtocol : SpdzWise<T> {

    typedef typename T::part_type check_type;
    typedef PostSacriRepRingShare<T::LENGTH + T::SECURITY, T::SECURITY> zero_check_type;

    DataPositions zero_usage;
    MaliciousBitOnlyRepPrep<zero_check_type> zero_prep;
    typename zero_check_type::MAC_Check zero_output;
    SubProcessor<zero_check_type> zero_proc;

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

    pthread_mutex_t queue_lock;

public:

    MaliciousRingProtocol(Player &P);

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    void exchange1();
    void exchange2();
    T finalize_mul(int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    void thread_handler();

    void zero_check(check_type t);

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

#endif