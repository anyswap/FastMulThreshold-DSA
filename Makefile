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
	rm -rf test/bin/*
	rm -rf test/log/*
	rm -rf test/nodekey/*
	rm -rf test/node1
	rm -rf test/node2
	rm -rf test/node3
	rm -rf test/node4
	rm -rf test/node5	

fmt:
	./gofmt.sh

gsmpc-test:
	./build.sh gsmpc-test
