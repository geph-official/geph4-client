#! /bin/sh
cargo lipo -v --locked --release;
mv target/universal/release/libgeph4client.a ../gephgui-ios/libGeph4Client/;
