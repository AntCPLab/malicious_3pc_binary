
#include "Protocols/SemiRingShare.h"
#include "Protocols/Semi3RingShare.h"
#include "Protocols/SemiRingProtocol.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Machines/Rep.hpp"
#include "Protocols/Replicated.hpp"

#include "Math/Integer.h"
#include "Processor/RingMachine.hpp"

int main(int argc, const char **argv) {

    HonestMajorityRingMachine<SemiRingShare, Semi3RingShare>(argc, argv);
}