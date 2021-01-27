# GEPH4 changes:

- Added library mode

# Socks2HTTP

This app converts socks5 proxy into HTTP proxy.

> This project is based on the source code of [shadowsocks/shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust).

## Usage

```
socks2http -h

socks2http 0.1.1
A simple http proxy which converts socks5 to http

USAGE:
    socks2http [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --local-addr <LOCAL_ADDR>      Local HTTP bind addr: `127.0.0.1:1081`
    -s, --socks5-addr <SOCKS5_ADDR>    Socks5 proxy addr: `1.1.1.1:1080`
```

## Log

You might want follow [this](https://crates.io/crates/env_logger)

## Maybe?

- Add ip/domain based proxy

## Extra

No extra dep needed, fast and smooth, powered by rust!
