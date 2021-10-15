# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: all gsmpc bootnode clean fmt gsmpc-client

all:
	./build.sh gsmpc bootnode gsmpc-client
	cp cmd/conf.toml bin/cmd
	@echo "Done building."

gsmpc:
	./build.sh gsmpc
	@echo "Done building."

bootnode:
	./build.sh bootnode
	@echo "Done building."

gsmpc-client:
	./build.sh gsmpc-client
	@echo "Done building."

clean:
	rm -fr bin/cmd/*
	rm -rf test/bin/gsmpctest
	rm -rf test/bin/bootnodetest
	rm -rf test/bin/gsmpc-client-test
	rm -rf test/log/*.log
	rm -rf test/nodedata/node*
	rm -rf test/nodekey/*.key

fmt:
	./gofmt.sh

gsmpc-test:
	./build.sh gsmpc-test
