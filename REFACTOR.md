# Why refactor?

Currently, we extensively use globals, mostly `once_cell` statics.

This is niceish for a binary crate, but we want to refactor geph4-client to be a proper library crate.

This has several benefits:

- iOS support is easier and more robust
  - iOS does not support multiple processes, so currently we use a hack where `geph4-client` is compiled as a C library with a single function that calls the `main` function. But that's a very bad hack overall.
- Geph can be _embedded_ into GUIs like `gephgui-wry` rather than separately compiled and packaged in. This simplifies coding and packaging greatly.

# The interface after refactoring

- A `GephClient` struct, which can be constructed by passing in a configuration struct. This `GephClient` struct will have methods like `send_vpn`, `recv_vpn`, `tcp_connect`, `exit_list`, and `stats`. It can be turned on and off at any time, so it will also have `connect`, `reconnect`, and `disconnect` methods.
- A `GephClientProxy` struct, which manages proxying by TUN, SOCKS5, etc, also configured by passing in a configuration struct. This is a conditionally-compiled component.

`geph4-client` will maintain its old legacy interface, but also support reading in a `--client-config` and `--proxy-config` through YAML.

# Usage in `gephgui-wry`

This is relatively straightforward, given that `gephgui-wry` is also a Rust program. The main thing to note would be that `gephgui-wry` itself needs to stay in the foreground, so e.g. tray support is crucial.

Before we make those changes, we can still use `geph4-client` with the old CLI interface.

# Usage in `geph-android`

We can still use the `geph4-client` CLI as a drop-in, but eventually should move to compiling `geph4-client` as a JNI library.

We can do something like this: https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html

This would require designing a **good** C API for `geph4-client`, that involves constructing a `struct geph_client *`, passing it to functions like `geph_send_vpn(struct geph_client *, char *, unsigned int)`, and manually freeing clients by calling something like `geph_free(struct geph_client *)`. That should not be _too_ hard, and we need that for iOS anyway. This C API can live in a special helper crate.

(One good way would be to represent a `geph_client` as a index into a concurrent slab, which prevents any memory safety issues.)

# Usage in iOS

We call the C API.
