# Introduction
Fast Multiparty Threshold DSA is a distributed key generation and distributed signature service that can serve as a distributed custodial solution.

*Note : smpc-walletService is considered beta software. We make no warranties or guarantees of its security or stability.*

# Install from code
# Prerequisites
1. VPS server with 1 CPU and 2G mem
2. Static public IP
3. Golang ^1.12

# Setting Up
## Clone The Repository
To get started, launch your terminal and download the latest version of the SDK.
```
mkdir -p $GOPATH/src/github.com/anyswap

cd $GOPATH/src/github.com/anyswap

git clone https://github.com/anyswap/FastMulThreshold-DSA.git
```
## Build
Next compile the code.  Make sure you are in FastMulThreshold-DSA directory.
```
cd FastMulThreshold-DSA && make
```

## Run
First generate the node key: 
```
./bin/cmd/gsmpc --genkey node1.key
```

then run the smpc node 7x24 in the background:
```
nohup ./bin/cmd/gsmpc --nodekey node1.key &
```
The `gsmpc` will provide rpc service, the default RPC port is port 4449.

