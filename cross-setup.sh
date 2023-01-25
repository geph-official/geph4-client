#!/bin/sh

git clone --recursive https://github.com/cross-rs/cross.git
cd cross
cargo build-docker-image armv7-linux-androideabi \
  --build-arg ANDROID_NDK=r25b \
  --build-arg ANDROID_SDK=21 \
  --build-arg ANDROID_VERSION=5.0.0_r1
cargo build-docker-image aarch64-linux-android \
  --build-arg ANDROID_NDK=r25b \
  --build-arg ANDROID_SDK=21 \
  --build-arg ANDROID_VERSION=5.0.0_r1