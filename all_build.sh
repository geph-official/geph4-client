#!/bin/sh
sh osx_build.sh
cross build --release --target i686-pc-windows-gnu --manifest-path=geph4-client/Cargo.toml
cross build --release --target x86_64-unknown-linux-musl --manifest-path=geph4-client/Cargo.toml
cross build --release --target x86_64-unknown-linux-musl --manifest-path=geph4-bridge/Cargo.toml
cross build --release --target armv7-linux-androideabi --manifest-path=geph4-client/Cargo.toml
cross build --release --target aarch64-linux-android --manifest-path=geph4-client/Cargo.toml
cross build --release --target armv7-unknown-linux-musleabihf --manifest-path=geph4-client/Cargo.toml
mkdir ~/repo/OUTPUT/
mv ~/repo/target/x86_64-unknown-linux-musl/release/geph4-client ~/repo/OUTPUT/geph4-client-linux-amd64
mv ~/repo/target/armv7-unknown-linux-musleabihf/release/geph4-client ~/repo/OUTPUT/geph4-client-linux-armv7
mv ~/repo/target/x86_64-unknown-linux-musl/release/geph4-bridge ~/repo/OUTPUT/geph4-bridge-linux-amd64
mv ~/repo/target/armv7-linux-androideabi/release/geph4-client ~/repo/OUTPUT/geph4-client-android-armv7
mv ~/repo/target/aarch64-linux-android/release/geph4-client ~/repo/OUTPUT/geph4-client-android-aarch64
mv ~/repo/target/i686-pc-windows-gnu/release/geph4-client.exe ~/repo/OUTPUT/geph4-client-windows-i386.exe
mv ~/repo/target/x86_64-apple-darwin/release/geph4-client ~/repo/OUTPUT/geph4-client-macos-amd64
exit 0