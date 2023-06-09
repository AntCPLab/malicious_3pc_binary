#ifndef PROTOCOLS_BGIN19MC_HPP_
#define PROTOCOLS_BGIN19MC_HPP_

#include "BGIN19MC.h"
#include "MaliciousRepMC.hpp"

template <class T>
BGIN19MC<T>::BGIN19MC() {
    needs_checking = false;
}

template <class T>
BGIN19MC<T>::~BGIN19MC() {
    if (needs_checking)
    {
        cerr << endl << "SECURITY BUG: insufficient checking" << endl;
        terminate();
    }
}

template <class T>
void BGIN19MC<T>::POpen(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P) {
    
    ReplicatedMC<T>::POpen(values, S, P);

}

template <class T>
void BGIN19MC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P) {
    
    ReplicatedMC<T>::POpen_End(values, S, P);

}

template <class T>
void BGIN19MC<T>::CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P) {
    
    (void) value;
    (void) shares;
    (void) P;

}

template<class T>
void BGIN19MC<T>::Check(const Player& P)
{
    (void) P;
}

#endif