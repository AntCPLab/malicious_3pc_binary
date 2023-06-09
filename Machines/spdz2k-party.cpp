/*
 * spdz2k-party.cpp
 *
 */

#include "GC/TinierSecret.h"
#include "Processor/Machine.h"
#include "Processor/RingOptions.h"
#include "Protocols/Spdz2kShare.h"
#include "Math/gf2n.h"
#include "Networking/Server.h"

#include "Processor/RingMachine.hpp"
#include "Math/Z2k.hpp"

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    opt.add(
        "64", // Default.
        0, // Required?
        1, // Number of args expected.
        0, // Delimiter if expecting multiple args.
        "SPDZ2k security parameter (default: 64)", // Help description.
        "-SP", // Flag token.
        "--spdz2k-security" // Flag token.
    );
    opt.parse(argc, argv);
    int s;
    opt.get("-SP")->getInt(s);
    opt.resetArgs();
    RingOptions ring_options(opt, argc, argv);
    int k = ring_options.R;
#ifdef VERBOSE
    cerr << "Using SPDZ2k with ring length " << k << " and security parameter "
            << s << endl;
#endif

#undef Z
#define Z(K, S) \
    if (s == S and k == K) \
        return spdz_main<Spdz2kShare<K, S>, Share<gf2n>>(argc, argv, opt);

    Z(64, 64)
    Z(64, 48)
    Z(72, 64)
    Z(72, 48)

#ifdef RING_SIZE
    Z(RING_SIZE, SPDZ2K_DEFAULT_SECURITY)
#endif

    else
    {
        if (s == SPDZ2K_DEFAULT_SECURITY)
        {
            ring_domain_error(k);
        }
        else
        {
            cerr << "not compiled for k=" << k << " and s=" << s << "," << endl;
            cerr << "add Z(" << k << ", " << s << ") to " << __FILE__ << " at line "
                    << (__LINE__ - 11) << " and create Machines/SPDZ2^" << k << "+"
                    << s << ".cpp based on Machines/SPDZ2^72+64.cpp" << endl;
            cerr << "Alternatively, compile with -DRING_SIZE=" << k
                    << " and -DSPDZ2K_DEFAULT_SECURITY=" << s << endl;
        }
        exit(1);
    }
}
