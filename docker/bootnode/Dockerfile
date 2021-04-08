# prepare
# 1st: cd ..; make gsmpc, cp bin/cmd/gsmpc docker
# 2nd: cd docker
FROM ubuntu:18.04
COPY bootnode /usr/local/bin/
COPY ./entrypoint-bootnode.sh /
RUN chmod +x /entrypoint-bootnode.sh
ENTRYPOINT ["/entrypoint-bootnode.sh"]

##include 1st and 2nd
##cp Dockerfile smpc6; cd smpc6
#FROM golang:1.13.5 AS builder
#WORKDIR /build
#COPY . .
#RUN make
#
#FROM ubuntu:18.04
#COPY bin/cmd/bootnode /usr/local/bin/
#COPY ./entrypoint-bootnode.sh /
#RUN chmod +x /entrypoint-bootnode.sh
#ENTRYPOINT ["/entrypoint-bootnode.sh"]

