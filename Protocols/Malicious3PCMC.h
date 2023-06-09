#ifndef PROTOCOLS_MALICIOUS3PCMC_H_
#define PROTOCOLS_MALICIOUS3PCMC_H_

#include "MaliciousRepMC.h"

template <class T>
class Malicious3PCMC : public MaliciousRepMC<T> {
protected:
    typedef MaliciousRepMC<T> super;
    bool needs_checking;

public:

    Malicious3PCMC(const typename T::mac_key_type& _, int __ = 0, int ___ = 0) : Malicious3PCMC() {
        (void)_;
        (void)__;
        (void)___;
    }

    Malicious3PCMC(const typename T::mac_key_type& _, Names& __, int ___ = 0, int ____ = 0) : Malicious3PCMC() {
        (void)_;
        (void)__;
        (void)___;
        (void)____;
    }

    Malicious3PCMC();
    ~Malicious3PCMC();

    void POpen(vector<typename T::open_type>& values,
            const vector<T>& S, const Player& P);

    void POpen_End(vector<typename T::open_type>& values,
            const vector<T>& S, const Player& P);

    void Check(const Player& P);
    void CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P);

};

#endif