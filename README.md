# Introduction
This is an implementation of multi-party threshold ECDSA (elliptic curve digital signature algorithm) based on [GG20: One Round Threshold ECDSA with Identifiable Abort](https://eprint.iacr.org/2020/540.pdf) and eddsa (Edwards curve digital signature algorithm),including the implementation of approval list connected with upper layer business logic and channel broadcasting based on P2P protocol.

It includes three main functions:

(1) Key generation is used to create secret sharing ("keygen") without trusted dealers.

(2) Use secret sharing,Paillier encryption and decryption to generate a signature ("signing").

(3) Preprocessing data before generating signature.(“pre-sign”).

When issuing the keygen/signing request command, there are two modes to choose from:

(1) Each participant node needs to approve the request command with its own account.It will first get the request command from the local approval list, and then approve or disagree.

(2) Each participant node does not need to approve the request command,which is agreed by default.

In distributed computing,message communication is required between each participant node.Firstly,the selected participants will form a group,and then P2P communication will be carried out within the group to exchange the intermediate calculation results of FastMPC algorithm.

The implementation is mainly developed in golang language,with a small amount of shell and C language.Leveldb database is used for local data storage,and third-party library codes such as Ethereum source code P2P and RPC modules and golang crypto are cited.

The implementation provides a series of RPC interfaces for external applications,such as bridge / router,to call in an RPC driven manner.The external application initiates a keygen/signaling request(RPC call),and then calls another RPC interface to obtain the approval list for approval.When the distributed calculation is completed,it will continue to call the RPC interface to obtain the calculation results.

*Note : fastMPC is considered beta software. We make no warranties or guarantees of its security or stability.*

# Install from code
# Prerequisites
1. VPS server with 1 CPU and 2G mem
2. Static public IP
3. Golang ^1.20

# Setting Up
## Clone The Repository
To get started, launch your terminal and download the latest version of the SDK.
```
git clone https://github.com/anyswap/FastMulThreshold-DSA.git
```
## Build
Next compile the code. Make sure you are in FastMulThreshold-DSA directory.
```
cd FastMulThreshold-DSA && make all
```

## Run By Default BootNode And Parametes
run the smpc node in the background:
```
nohup ./build/bin/gsmpc &
```
The `gsmpc` will provide rpc service, the default RPC port is port 4449.

## Manually Set Parameter To Run Node And Self-test 
[keygen-and-sign-workflow](https://github.com/anyswap/FastMulThreshold-DSA/wiki/keygen-and-sign-workflow)

## Local Test
It will take some time more than 15 minutes,please wait patiently!
```
make gsmpc-test
```

#Note

1.If you want to call RPC API, please wait at least 2 minutes after running the node.

2.If you want to call RPC API quickly more than once,please wait longer.

3.If you want to reboot a node, please wait 2 minute after closing node before restarting the node.


