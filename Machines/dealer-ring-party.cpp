/*
 * dealer-ring-party.cpp
 *
 */

#include "Protocols/DealerShare.h"
#include "Protocols/DealerInput.h"
#include "Protocols/Dealer.h"

#include "Processor/RingMachine.hpp"
#include "Processor/Machine.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/DealerPrep.hpp"
#include "Protocols/DealerInput.hpp"
#include "Protocols/DealerMC.hpp"
#include "Protocols/DealerMatrixPrep.hpp"
#include "Protocols/Beaver.hpp"
#include "Semi.hpp"
#include "GC/DealerPrep.h"

int main(int argc, const char** argv)
{
    HonestMajorityRingMachine<DealerRingShare, DealerShare>(argc, argv, 0);
}
