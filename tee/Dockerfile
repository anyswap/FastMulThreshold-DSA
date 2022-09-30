# Env for reproducible build, other version may affects reproducible build
FROM ubuntu:focal-20220801 AS build
ARG egover=1.0.0
RUN apt-get update && apt-get install -dy --no-install-recommends \
  build-essential \
  ca-certificates \
  clang-10 \
  cmake \
  git \
  libssl-dev \
  ninja-build \
  wget

# Install required packages
RUN apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  git \
  wget

# Download and install EGo
RUN wget https://github.com/edgelesssys/ego/releases/download/v${egover}/ego_${egover}_amd64.deb \
  && dpkg -i --force-depends ego_${egover}_amd64.deb

# Build smpc app
ARG smpcver=support-tee
RUN git clone --branch ${smpcver} --depth=1 https://github.com/anyswap/FastMulThreshold-DSA \
  && cd FastMulThreshold-DSA \
  && ego-go build -trimpath -v -o gsmpc ./cmd/gsmpc
RUN --mount=type=secret,id=signingkey,dst=/private.pem,required=true ego sign /FastMulThreshold-DSA/gsmpc

# Export the binary smpc app
FROM scratch AS export
COPY --from=build /FastMulThreshold-DSA/gsmpc /