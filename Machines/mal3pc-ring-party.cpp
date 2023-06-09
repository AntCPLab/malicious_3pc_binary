/*
 * sy-rep-ring-party.cpp
 *
 */

#include "Protocols/SpdzWiseRingShare.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/Malicious3PCShare.h"
#include "Protocols/SpdzWiseMC.h"
#include "Protocols/SpdzWiseRingPrep.h"
#include "Protocols/SpdzWiseInput.h"
#include "Protocols/MalRepRingPrep.h"
#include "Processor/RingOptions.h"
#include "GC/MaliciousCcdSecret.h"

#include "Protocols/BinaryCheck.hpp"
#include "Processor/RingMachine.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/SpdzWise.hpp"
#include "Protocols/SpdzWiseRing.hpp"
#include "Protocols/SpdzWisePrep.hpp"
#include "Protocols/SpdzWiseInput.hpp"
#include "Protocols/SpdzWiseShare.hpp"
#include "Protocols/PostSacrifice.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "Protocols/MaliciousRepPrep.hpp"
#include "Protocols/RepRingOnlyEdabitPrep.hpp"
#include "Protocols/Malicious3PCProtocol.hpp"
#include "Protocols/Malicious3PCMC.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Instruction.hpp"
#include "Processor/Machine.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    HonestMajorityRingMachineWithSecurity<Malicious3PCRingShare, Malicious3PCFieldShare>(
            argc, argv, opt);
}
