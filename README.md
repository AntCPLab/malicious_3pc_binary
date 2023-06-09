# Efficient 3PC for Binary Circuits with Application to Maliciously-Secure DNN Inference

## Introduction

This repo is an implementation about our work published in USENIX Sec '23. And we also implement the [BGIN19](https://eprint.iacr.org/2019/1390) protocol for comparison.

This repo is based on [MP-SPDZ](https://github.com/data61/MP-SPDZ) framework by Data61. 

## Files

All protocols in MP-SPDZ begin with files which name ends with 'Share.h'. For example, our protocol was defined in 'Malicious3PCShare.h'. 
In the 'xxShare.h' code, there defines the protocol class (in our protocol, this is Malicious3PCProtocol) and some class for input, output. Here we only focus on the Protocol class.
All the code about the Protocol are in files which name ends with 'Protocol.h/hpp'. In our protocol, this is 'Malicious3PCProtocol.h/hpp'.

BGIN19 is in files start with 'BGIN19'. Such as 'BGIN19Share.h', 'BGIN19Protocol.h/hpp'. And the main logic of BGIN19 is in 'BGIN19Protocol.hpp'.

## Environment setup

There is no other specific instructions than the basic MP-SPDZ setup procedure for our protocol. You can do the following steps to run our protocol on **Linux** machine:

1. Clone the repo, and checkout to branch feat-bgin19.
2. Run `sudo apt update`, `sudo apt-get install automake build-essential git libboost-dev libboost-thread-dev libntl-dev libsodium-dev libssl-dev libtool m4 python3 texinfo yasm` to install the necessary packages.
3. Run `make tldr` to compile libraries.
4. Run `make mal3pc-field-party.x` to compile our protocol. If you want to compile BGIN19, then run `make bgin19-field-party.x`.
5. Run `./Scripts/setup-ssl.sh` to generate the certificates for authenticated communication.
6. Finally, run `./Scripts/mal3pc-field.sh circuit_name args` to run our protocol on some compiled circuit and with the specific arguments. The compilation and arguments will be introduced below.

## Compile circuits

In the folder `Programs/Source`, there are lots of source code with .mpc ext. To compile some circuit, such as sbit_test.mpc, just run `./compile.py sbit_test` in root dir of the repo. After that, you can replace `circuit_name` with `sbit_test`.

## Arguments

There are two main arguments we used here: binary_batch_size, max_status.

### binary batch size

This is easy to understand. The size of AND gates that we verify in one batch.

### max status

This argument is considered when we do implementation. It means that we will store `max_status` batches to do verification together, in order to cut down the communication rounds.
Assume we have 10 batches AND gates to verification, if we verify them immediately, then the communication rounds will be 10 times some const (10 * k), assume k rounds in each verification. But if we put them together, we can send data together and only need k rounds.

### commands

Assume now we want to run our protocol on circuit 1M-100, with binary_batch_size = 100000 and max_status = 10, we can run the following command:
`./Scripts/mal3pc-field.sh sbit_test -bb 300000 -ms 10`

## WAN setting

Many of our experiments were ran in WAN setting. This is easy to do. When you run the command above, you can see that actually three commands were executed seperately, in the following format:
`./protocol_binary.x party_id circuit_name -bb batchsize -ms maxstatus -h host -p port`

So if we want to perform the three party in three different machine, we just need the ip address of party 0, and replace the host of party 0 as `0.0.0.0` and host of other parties as the ip of party0.
And, as for the certificate, the easiest way is to copy all .pem and .key files in dir Player-Data in party 0 to other parties' same directory, and run rehash Player-Data. See official document of MP-SPDZ for detail.