#!/bin/bash

set -eu

if [ ! -f "build.sh" ]; then
        echo "$0 must be run from the root of the repository."
	    exit 2
fi

mod3=gsmpc-test-2-2
mod1=gsmpc-test
mod2=gsmpc-test-clean
if [ $1 = $mod2 ]; then
	rm -rf test/bin/gsmpctest
	rm -rf test/bin/bootnodetest
	rm -rf test/bin/gsmpc-client-test
	rm -rf test/reqaddr.sh
	rm -rf test/sign.sh
	rm -rf test/log/*.log*
	rm -rf test/nodedata/node*
	rm -rf test/nodekey/*.key
	for i in `ls test/tmp/`;do
        if [ "$i" != readme ];then 
            rm -rf test/tmp/$i;
        fi;
        done;
    exit
fi

#2-2 test
if [ $1 = $mod3 ]; then
    chmod a+x ./gsmpc-test-2-2.sh
    chmod a+x ./bootnode-test.sh
    ./gsmpc-test-2-2.sh $(pwd) 5871 "" EC256K1
    exit
fi

if [ $1 = $mod1 ]; then
    chmod a+x ./gsmpc-test.sh
    chmod a+x ./bootnode-test.sh
    ./gsmpc-test.sh $(pwd) 5871 "" EC256K1
else
    export GO111MODULE=on
    export GOPROXY=https://goproxy.io
    export GOPROXY=https://gonexus.dev
    export GOPROXY=https://athens.azurefd.net
    export GOPROXY=https://gocenter.io
    export GOPROXY=https://proxy.golang.org
    export GOPROXY=https://goproxy.cn
    export GOPROXY=https://mirrors.aliyun.com/goproxy/

    for mod in $@; do
        go run build/ci.go install ./cmd/$mod
    done
fi

#/* vim: set ts=4 sts=4 sw=4 et : */

