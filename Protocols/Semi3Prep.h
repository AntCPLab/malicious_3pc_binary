/*
 * Semi3Prep.h
 *
 */

#ifndef PROCESSOR_SEMI3PREP_H_
#define PROCESSOR_SEMI3PREP_H_

#include "Tools/Exceptions.h"
#include "Protocols/ReplicatedPrep.h"

template<class T> class SubProcessor;
class DataPositions;

// preprocessing facility
template<class T>
class Semi3Prep : public ReplicatedPrep<T>
{
    public:

    Semi3Prep(SubProcessor<T>* proc, DataPositions& usage) :
            ReplicatedPrep<T>(proc, usage)
    {
    }

    Semi3Prep(DataPositions& usage, int = 0) :
            ReplicatedPrep<T>(usage)
    {
    }

    template<class U>
    Semi3Prep(DataPositions& usage, GC::ShareThread<U>&, int = 0) :
            ReplicatedPrep<T>(0, usage)
    {
    }

    
};

#endif /* PROCESSOR_SEMI3PREP_H_ */
