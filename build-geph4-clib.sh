#!/usr/bin/env bash
# building
cargo lipo --release

# moving files to the ios project
inc=/Users/miyuruasuka/Desktop/geph4-ios/include
libs=/Users/miyuruasuka/Desktop/geph4-ios/libs

rm -rf ${inc} ${libs}

mkdir ${inc}
mkdir ${libs}

cp /Users/miyuruasuka/geph4/src/geph4client.h ${inc}
cp /Users/miyuruasuka/geph4/target/universal/release/libgeph4client.a ${libs}

