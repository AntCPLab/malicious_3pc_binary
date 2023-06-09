#ifndef PROTOCOLS_BGIN19MC_H_
#define PROTOCOLS_BGIN19MC_H_

#include "MaliciousRepMC.h"

template <class T>
class BGIN19MC : public MaliciousRepMC<T> {
protected:
    typedef MaliciousRepMC<T> super;
    bool needs_checking;

public:

    BGIN19MC(const typename T::mac_key_type& _, int __ = 0, int ___ = 0) : BGIN19MC() {
        (void)_;
        (void)__;
        (void)___;
    }

    BGIN19MC(const typename T::mac_key_type& _, Names& __, int ___ = 0, int ____ = 0) : BGIN19MC() {
        (void)_;
        (void)__;
        (void)___;
        (void)____;
    }

    BGIN19MC();
    ~BGIN19MC();

    void POpen(vector<typename T::open_type>& values,
            const vector<T>& S, const Player& P);

    void POpen_End(vector<typename T::open_type>& values,
            const vector<T>& S, const Player& P);

    void Check(const Player& P);
    void CheckFor(const typename T::open_type& value, const vector<T>& shares, const Player& P);

};

#endif