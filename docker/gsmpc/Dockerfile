# prepare
# 1st: cd smpc6; make gsmpc; cp bin/cmd/gsmpc docker/gsmpc
# 2nd: cd docker/gsmpc
FROM ubuntu:18.04
COPY gsmpc gsmpc-client /usr/local/bin/
COPY ./entrypoint-gsmpc.sh /
RUN chmod +x /entrypoint-gsmpc.sh
ENTRYPOINT ["/entrypoint-gsmpc.sh"]

##include 1st and 2nd
##cp Dockerfile smpc6; cd smpc6
#FROM golang:1.13.5 AS builder
#WORKDIR /build
#COPY . .
#RUN make
#
#FROM ubuntu:18.04
#COPY bin/cmd/gsmpc /usr/local/bin/
#COPY ./entrypoint-gsmpc.sh /
#RUN chmod +x /entrypoint-gsmpc.sh
#ENTRYPOINT ["/entrypoint-gsmpc.sh"]

