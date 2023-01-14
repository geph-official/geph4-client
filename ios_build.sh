#! /bin/sh
cargo lipo --release;
mv target/universal/release/libgeph4client.a ../gephgui-ios/libGeph4Client/;
