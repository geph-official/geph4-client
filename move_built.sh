#!/bin/sh
VERSION=$(cargo pkgid | cut -d "#" -f2)
mkdir -p ./OUTPUT/$VERSION/
mv ./target/x86_64-unknown-linux-musl/release/geph4-client ./OUTPUT/$VERSION/geph4-client-linux-amd64
mv ./target/x86_64-unknown-linux-gnu/release/geph4-vpn-helper ./OUTPUT/$VERSION/geph4-vpn-helper-linux-amd64
mv ./target/armv7-unknown-linux-musleabihf/release/geph4-client ./OUTPUT/$VERSION/geph4-client-linux-armv7
mv ./target/armv7-linux-androideabi/release/geph4-client ./OUTPUT/$VERSION/geph4-client-android-armv7
mv ./target/aarch64-linux-android/release/geph4-client ./OUTPUT/$VERSION/geph4-client-android-aarch64
mv ./target/x86_64-linux-android/release/geph4-client ./OUTPUT/$VERSION/geph4-client-android-amd64
mv ./target/i686-linux-android/release/geph4-client ./OUTPUT/$VERSION/geph4-client-android-i386
mv ./target/i686-pc-windows-msvc/release/geph4-client.exe ./OUTPUT/$VERSION/geph4-client-windows-i386.exe
mv ./target/release/geph4-client.exe ./OUTPUT/$VERSION/geph4-client-windows-i386.exe
mv ./target/x86_64-apple-darwin/release/geph4-client ./OUTPUT/$VERSION/geph4-client-macos-amd64
exit 0