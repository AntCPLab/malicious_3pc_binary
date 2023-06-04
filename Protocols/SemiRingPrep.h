/*
 * SemiRingPrep.h
 *
 */

#ifndef PROCESSOR_SEMIRINGPREP_H_
#define PROCESSOR_SEMIRINGPREP_H_

#include "Tools/Exceptions.h"
#include "Protocols/ReplicatedPrep.h"
#include "Rep3Share.h"

template<class T> class SubProcessor;
class DataPositions;

// preprocessing facility
template<class T>
class SemiRingPrep : public ReplicatedPrep<T>
{
public:


    SemiRingPrep(SubProcessor<T>* proc, DataPositions& usage) :
            ReplicatedPrep(proc, usage)
    {
    }

    SemiRingPrep(DataPositions& usage, int = 0) :
            SemiRingPrep(0, usage)
    {
    }

    template<class U>
    SemiRingPrep(DataPositions& usage, GC::ShareThread<U>&, int = 0):
            SemiRingPrep(0, usage)
    {
    }

    array<T, 3> get_triple(int n_bits);
    

};

#endif /* PROCESSOR_SEMIRINGPREP_H_ */
