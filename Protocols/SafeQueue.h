#ifndef FFMPEGS_SAFE_QUEUE_H
#define FFMPEGS_SAFE_QUEUE_H
 
#pragma once
#include <queue>
#include <pthread.h>
 
using namespace std;
 

class CV {
private:
    std::mutex mx;
    std::condition_variable cv;
    int n_times;

public:

    CV(): n_times(0) {}
    ~CV() {}
    
    void lock()
    {
        mx.lock();
    }

    void unlock()
    {
        mx.unlock();

    }

    void wait()
    {
        std::unique_lock<std::mutex> lock(mx);
        if (--n_times < 0) {
            cv.wait(lock);
        }
    }

    void signal()
    {
        std::unique_lock<std::mutex> lock(mx);
        if (++n_times <= 0) {
            cv.notify_one();
        }
    }
};

template <typename T>
class SafeQueue{
public:
    SafeQueue() {}
    ~SafeQueue() {}
 
    void push(T t){
        cv.lock();
        q.push(t);
        cv.signal();
        cv.unlock();
 
    }
    T pop(){
        cv.lock();
        if(q.empty()) {
            cv.wait();
        }
        T t = q.front();
        q.pop();
 
        cv.unlock();

        return t;
    }

    // T front() {
    //     return q.front();
    // }

    size_t size() {
        cv.lock();
        size_t sz = q.size();
        cv.unlock();
        return sz;
    }

    bool empty() {
        cv.lock();
        bool ep = q.empty();
        cv.unlock();
        return ep;
    }
private:
    // 如何保证对这个队列的操作是线程安全的？引入互斥锁
    queue<T> q;
    CV cv;
    // std::mutex queue_lock;
 
};

template <typename T>
class FixedQueue {
private:
    size_t _size;
    T *data;
    size_t head, tail;

public:
    FixedQueue(): _size(0), head(0), tail(0) {}
    FixedQueue(size_t sz): _size(sz), head(0), tail(0) {
        data = new T[sz];
    }

    ~FixedQueue() {
        delete[] data;
    }

    void print_log() {
        cout << tail << " -> " << head << ", size = " << size() << ", alloced size = " << _size << endl;
    }

    void init(size_t sz) {
        if (_size != 0) {
            delete[] data;
        }
        data = new T[sz];
        _size = sz;
    }

    inline void resize(size_t length) {

        if (length < _size) {
            return ;
        }

        // print_log();

        size_t sz = _size;
        T *tmp = new T[length];

        if (head > tail) {
            memcpy(tmp, data + tail, sizeof(T) * sz);
        }
        else {
            memcpy(tmp + (sz - tail), data, sizeof(T) * head);
            memcpy(tmp, data + tail, sizeof(T) * (sz - tail));
        }
        head = sz; tail = 0;
        delete[] data;
        data = tmp;
        _size = length;
    }

    inline void push(T one_data) {
        data[head++] = one_data;

        if (head >= _size)  head -= _size;

        if (head == tail) {
            // cout << "in push, resize from " << _size << " to " << _size * 2 << endl;
            resize(_size * 2);
        }
        
        else if (head >= _size) {
            head -= _size;
        }
    }

    inline void pop(size_t number_poped) {
        tail += number_poped;
        while (tail >= _size)   tail -= _size;
    }

    void pop() {
        pop(1);
    }

    inline T front() {
        return data[tail];
    }

    inline bool empty() {
        return head == tail;
    }

    inline size_t size() {
        long sz = (long) head - (long) tail;
        if (sz < 0) {
            sz += _size;
        }
        return (size_t) sz;
    }

    inline size_t alloc_size() {
        return _size;
    }

    inline T operator[] (const int a) {
        size_t idx = tail + a;
        while (idx >= _size) {
            idx -= _size;
        }
        while (idx < 0) {
            idx += _size;
        }
        return data[idx];
    }

};
 
#endif //FFMPEGS_SAFE_QUEUE_H