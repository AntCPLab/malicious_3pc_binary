/*
 * mal3pc-field-party.cpp
 *
 */

#include "Protocols/Malicious3PCShare.h"
#include "Processor/FieldMachine.hpp"
#include "Machines/Rep.hpp"
#include "Machines/MalRep.hpp"
#include "Math/gfp.hpp"

int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<Malicious3PCShare>(argc, argv);
}
