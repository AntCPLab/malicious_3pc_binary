#ifndef PROTOCOLS_MALICIOUS3PCMC_HPP_
#define PROTOCOLS_MALICIOUS3PCMC_HPP_

#include "Malicious3PCMC.h"
#include "MaliciousRepMC.hpp"

template <class T>
Malicious3PCMC<T>::Malicious3PCMC() {
    needs_checking = false;
}

template <class T>
Malicious3PCMC<T>::~Malicious3PCMC() {
    if (needs_checking)
    {
        cerr << endl << "SECURITY BUG: insufficient checking" << endl;
        terminate();
    }
}

template <class T>
void Malicious3PCMC<T>::POpen(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P) {
    
    ReplicatedMC<T>::POpen(values, S, P);

}

template <class T>
void Malicious3PCMC<T>::POpen_End(vector<typename T::open_type>& values,
        const vector<T>& S, const Player& P) {
    
    ReplicatedMC<T>::POpen_End(values, S, P);

}

template <class T>
void Malicious3PCMC<T>::CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P) {
    
    (void) value;
    (void) shares;
    (void) P;

}

template<class T>
void Malicious3PCMC<T>::Check(const Player& P)
{
    (void) P;
}

#endif