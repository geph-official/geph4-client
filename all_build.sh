#!/bin/sh
sh osx_build.sh
CARGO_TARGET_DIR=/tmp/windows-amd64 cross build --release --locked --target x86_64-pc-windows-gnu --manifest-path=geph4-client/Cargo.toml &
CARGO_TARGET_DIR=/tmp/windows-i386 cross build --release --locked --target i686-pc-windows-gnu --manifest-path=geph4-client/Cargo.toml &
CARGO_TARGET_DIR=/tmp/linux-amd64 cross build --release --locked  --target x86_64-unknown-linux-musl --manifest-path=geph4-client/Cargo.toml &
CARGO_TARGET_DIR=/tmp/linux-amd64-helper cross build --release --locked  --target x86_64-unknown-linux-gnu --manifest-path=geph4-vpn-helper/Cargo.toml &
CARGO_TARGET_DIR=/tmp/linux-armv7 cross build --release --locked  --target armv7-linux-androideabi --manifest-path=geph4-client/Cargo.toml &
CARGO_TARGET_DIR=/tmp/android-aarch64 cross build --release --locked  --target aarch64-linux-android --manifest-path=geph4-client/Cargo.toml &
CARGO_TARGET_DIR=/tmp/android-armv7 cross build --release --locked  --target armv7-unknown-linux-musleabihf --manifest-path=geph4-client/Cargo.toml &
wait;
mkdir ./OUTPUT/
mv /tmp/linux-amd64/x86_64-unknown-linux-musl/release/geph4-client ./OUTPUT/geph4-client-linux-amd64
mv /tmp/linux-amd64-helper/x86_64-unknown-linux-gnu/release/geph4-vpn-helper ./OUTPUT/geph4-vpn-helper-linux-amd64
mv /tmp/linux-armv7/armv7-unknown-linux-musleabihf/release/geph4-client ./OUTPUT/geph4-client-linux-armv7
mv /tmp/android-armv7/armv7-linux-androideabi/release/geph4-client ./OUTPUT/geph4-client-android-armv7
mv /tmp/android-aarch64/aarch64-linux-android/release/geph4-client ./OUTPUT/geph4-client-android-aarch64
mv /tmp/windows-amd64/x86_64-pc-windows-gnu/release/geph4-client.exe ./OUTPUT/geph4-client-windows-amd64.exe
mv /tmp/windows-i386/i686-pc-windows-gnu/release/geph4-client.exe ./OUTPUT/geph4-client-windows-i386.exe
mv ./target/x86_64-apple-darwin/release/geph4-client ./OUTPUT/geph4-client-macos-amd64
exit 0
