/*
 * mal3pc-field-party.cpp
 *
 */

#include "Protocols/BGIN19Share.h"
#include "Processor/FieldMachine.hpp"
#include "Machines/Rep.hpp"
#include "Machines/MalRep.hpp"
#include "Math/gfp.hpp"

int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<BGIN19Share>(argc, argv);
}
