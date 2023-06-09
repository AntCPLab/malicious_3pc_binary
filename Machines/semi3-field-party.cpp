/*
 * replicated-field-party.cpp
 *
 */

#include "Processor/FieldMachine.hpp"
#include "Processor/Machine.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Instruction.hpp"
// #include "Processor/OnlineMachine.hpp"

#include "Protocols/Semi3Share.h"
#include "Protocols/Semi3Protocol.hpp"
#include "Protocols/MalRepRingPrep.h"
#include "Protocols/ReplicatedPrep2k.h"
#include "Protocols/MAC_Check_Base.hpp"
#include "Protocols/Beaver.hpp"
#include "Protocols/Spdz2kPrep.hpp"

#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"

#include "Math/gfp.hpp"
#include "Math/Z2k.hpp"


int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<Semi3Share>(argc, argv);
}