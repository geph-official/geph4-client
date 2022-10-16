#!/bin/bash
sudo apt update
sudo apt install \
    clang \
    gcc \
    g++ \
    zlib1g-dev \
    libmpc-dev \
    libmpfr-dev \
    libgmp-dev \
    build-essential

# Add macOS Rust target
rustup target add x86_64-apple-darwin

git clone https://github.com/tpoechtrager/osxcross
cd osxcross
wget -nc https://s3.dockerproject.org/darwin/v2/MacOSX10.10.sdk.tar.xz
mv MacOSX10.10.sdk.tar.xz tarballs/
UNATTENDED=yes OSX_VERSION_MIN=10.7 ./build.sh
PATH="$(pwd)/target/bin:$PATH" \
CC=o64-clang \
CXX=o64-clang++ \
RUSTFLAGS='-C link-arg=-s' cargo build --release  --locked --target x86_64-apple-darwin 