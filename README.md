# Malicious-3PC

Usage: After pull the repository, run:
```
sudo apt update
sudo apt install automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm
make tldr
```

then the environment will automatically prepared. And you can build other protocols.

## Semi-Honest

Protocol name is semi-ring, and the protocol implementation is in:
- SemiRingProtocol.h
- SemiRingProtocol.hpp

Share is in :
- SemiRingShare.h

If you want to compile the protocol, just run:
```
make semi-ring
```

and the script file is in `Scripts/semi-ring.sh`.

## Malicious

Our binary check is in Protocols/Malicious3PCProtocol.h, and the VM file is Machines/mal3pc-ring-party.cpp. If you want to compile this protocol, please DO NOT FORGET to uncomment GC/ShareThread.hpp: line 80 `protocol->finalize_check();` and comment line 81.

## About mpir:

If any error occurs in make. According to the error log, if it's about `mpir`, try to figure out the following:
- mpir directory is not empty. If it is, you have to run `git clone https://github.com/wbhart/mpir.git`.
- make sure mpir is correctly installed. You can check the INSTALL file in mpir.
- Other errors mostly can be found in the issue of mpir project.
